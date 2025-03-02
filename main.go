package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	bolt "go.etcd.io/bbolt"
)

const (
	cacheFile      = "crtsh_cache.db"
	defaultTimeout = 30 * time.Second
	flowTTL        = 120 * time.Second // TTL for both flows
	concurrency    = 50                // Increased concurrency for second flow
	maxRetries     = 3                 // Max retries for failed requests
	retryDelay     = 5 * time.Second   // Delay between retries
)

type Cert struct {
	NameValue string `json:"name_value"`
}

// CacheEntry represents the structure stored in BoltDB
type CacheEntry struct {
	Subsets map[int64][]string `json:"subsets"` // Timestamp -> Domains fetched at that time
}

var (
	domain    string
	verbose   bool
	timeout   time.Duration
	fromCache bool
)

var rootCmd = &cobra.Command{
	Use:   "crtsh",
	Short: "Fetch subdomains from crt.sh",
	Long: `A fast CLI tool to fetch subdomains from crt.sh certificate transparency logs
with caching support and concurrent processing. Cache persists indefinitely, accumulates new records,
and tracks fetch timestamps per subset of domains.`,
	RunE: run,
}

func init() {
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to query (required)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().DurationVarP(&timeout, "timeout", "t", defaultTimeout, "API request timeout (unused in fetch flows)")
	rootCmd.Flags().BoolVarP(&fromCache, "from-cache", "c", false, "Print data from cache only")

	if err := rootCmd.MarkFlagRequired("domain"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	domain = strings.ToLower(domain)

	if verbose {
		fmt.Printf("Querying domain: %s (fetch TTL: %v, concurrency: %d)\n", domain, flowTTL, concurrency)
	}

	// Open BoltDB
	db, err := bolt.Open(cacheFile, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return fmt.Errorf("failed to open cache: %w", err)
	}
	defer db.Close()

	// Handle --from-cache flag
	if fromCache {
		cached, err := getFromCacheRaw(db, domain)
		if err != nil {
			return fmt.Errorf("failed to read from cache: %w", err)
		}
		if cached == nil || len(cached.Subsets) == 0 {
			fmt.Println("No cached data found for", domain)
			return nil
		}
		totalDomains := countDomains(cached.Subsets)
		if verbose {
			fmt.Printf("Retrieved %d domains from cache across %d subsets\n", totalDomains, len(cached.Subsets))
		}
		printDomainsWithSubsetTimestamps(cached.Subsets)
		return nil
	}

	// Check cache first (normal operation)
	cached, err := getFromCache(db, domain)
	if err == nil && cached != nil && len(cached.Subsets) > 0 {
		if verbose {
			fmt.Println("Retrieved results from cache")
		}
		printDomainsOnly(cached.Subsets)
		return nil
	}

	if verbose {
		fmt.Println("Cache miss, fetching from crt.sh API...")
	}

	// Fetch from API if cache miss
	start := time.Now()
	domains, err := fetchDomains(domain)
	if err != nil {
		return err
	}

	// Update cache with final combined results
	if err := storeInCache(db, domain, domains, start); err != nil {
		return fmt.Errorf("failed to update cache: %w", err)
	}

	if verbose {
		fmt.Printf("Fetched %d domains in %v\n", len(domains), time.Since(start))
	}

	// Print the newly fetched domains
	printDomainsOnly(map[int64][]string{start.Unix(): domains})
	return nil
}

func fetchDomains(domain string) ([]string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			MaxIdleConnsPerHost: concurrency,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// First flow: Finding root domains (CN endpoint) with 120s TTL
	cnDomains, err := fetchWithRetry(client, "CN", domain, "Finding root domains")
	if err != nil {
		return nil, err
	}

	if verbose {
		fmt.Printf("Finding root domains: Fetched %d domains from CN endpoint\n", len(cnDomains))
	}

	// Second flow: Additional roots from the primary roots (q endpoint), concurrent with 120s TTL per query
	domainMap := sync.Map{}
	for _, d := range cnDomains {
		domainMap.Store(d, struct{}{}) // Include original domains
	}

	totalDomains := len(cnDomains)
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency) // Semaphore to limit concurrency
	var wg sync.WaitGroup

	for i, d := range cnDomains {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		go func(index int, primaryDomain string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			qDomains, err := fetchWithRetry(client, "q", primaryDomain, "Additional roots from the primary roots")
			if err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "Error fetching additional roots for %s: %v\n", primaryDomain, err)
				}
				return
			}

			newDomains := 0
			for _, qd := range qDomains {
				if _, exists := domainMap.LoadOrStore(qd, struct{}{}); !exists {
					newDomains++
				}
			}

			mu.Lock()
			totalDomains += newDomains
			if verbose {
				fmt.Printf("Additional roots from the primary roots: Processed %d/%d domains, found %d new domains for %s, total unique domains: %d\n",
					index+1, len(cnDomains), newDomains, primaryDomain, totalDomains)
			}
			mu.Unlock()
		}(i, d)
	}

	wg.Wait()

	// Combine all results into final list
	finalDomains := make([]string, 0, totalDomains)
	domainMap.Range(func(key, _ interface{}) bool {
		finalDomains = append(finalDomains, key.(string))
		return true
	})
	sort.Strings(finalDomains)

	return finalDomains, nil
}

func fetchWithRetry(client *http.Client, endpoint, domain, flowName string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?%s=%%25.%s&output=json", endpoint, domain)
	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), flowTTL)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "%s: Attempt %d/%d failed for %s: %v\n", flowName, attempt, maxRetries, domain, err)
			}
			if attempt == maxRetries {
				return nil, fmt.Errorf("failed to fetch from crt.sh %s endpoint after %d retries: %w", endpoint, maxRetries, err)
			}
			time.Sleep(retryDelay)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			if verbose {
				fmt.Fprintf(os.Stderr, "%s: Rate limited for %s, retrying after delay...\n", flowName, domain)
			}
			time.Sleep(retryDelay * time.Duration(attempt)) // Exponential backoff
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s endpoint HTTP status %d for %s", endpoint, resp.StatusCode, domain)
		}

		var certs []Cert
		if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
			return nil, err
		}

		domains, err := processCerts(certs, domain)
		if err != nil {
			return nil, err
		}
		return domains, nil
	}
	return nil, fmt.Errorf("unexpected exit from retry loop for %s", domain)
}

func processCerts(certs []Cert, domain string) ([]string, error) {
	domainPattern := regexp.MustCompile(`^(.+\.)*` + regexp.QuoteMeta(domain) + `$`)
	uniqueDomains := sync.Map{}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range certs {
		wg.Add(1)
		sem <- struct{}{}
		go func(cert Cert) {
			defer wg.Done()
			defer func() { <-sem }()

			lines := strings.Split(cert.NameValue, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				lowerLine := strings.ToLower(line)
				if domainPattern.MatchString(lowerLine) {
					if strings.HasPrefix(lowerLine, "*.") {
						lowerLine = strings.TrimPrefix(lowerLine, "*.")
					}
					uniqueDomains.Store(lowerLine, struct{}{})
				}
			}
		}(certs[i])
	}

	wg.Wait()

	var domains []string
	uniqueDomains.Range(func(key, _ interface{}) bool {
		domains = append(domains, key.(string))
		return true
	})
	sort.Strings(domains)
	return domains, nil
}

// getFromCacheRaw retrieves raw cache data
func getFromCacheRaw(db *bolt.DB, domain string) (*CacheEntry, error) {
	var entry CacheEntry
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(domain))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &entry)
	})
	if err != nil {
		return nil, err
	}
	if entry.Subsets == nil {
		return nil, nil
	}
	return &entry, nil
}

// getFromCache retrieves cached data without TTL check
func getFromCache(db *bolt.DB, domain string) (*CacheEntry, error) {
	var entry CacheEntry
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("domains"))
		if b == nil {
			return nil
		}
		data := b.Get([]byte(domain))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &entry)
	})
	if err != nil {
		return nil, err
	}
	if entry.Subsets == nil {
		return nil, nil
	}
	return &entry, nil
}

// storeInCache adds new domains as a subset with the fetch timestamp
func storeInCache(db *bolt.DB, domain string, newDomains []string, fetchTime time.Time) error {
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("domains"))
		if err != nil {
			return err
		}

		// Get existing subsets
		existingData := b.Get([]byte(domain))
		var entry CacheEntry
		if existingData != nil {
			if err := json.Unmarshal(existingData, &entry); err != nil {
				return err
			}
		}
		if entry.Subsets == nil {
			entry.Subsets = make(map[int64][]string)
		}

		// Add new subset if there are new domains
		if len(newDomains) > 0 {
			timestamp := fetchTime.Unix()
			// Deduplicate within the new subset
			domainMap := make(map[string]struct{})
			for _, d := range newDomains {
				domainMap[d] = struct{}{}
			}
			// Only add new domains not present in any existing subset
			for _, existingDomains := range entry.Subsets {
				for _, d := range existingDomains {
					delete(domainMap, d)
				}
			}
			if len(domainMap) > 0 {
				newSubset := make([]string, 0, len(domainMap))
				for d := range domainMap {
					newSubset = append(newSubset, d)
				}
				sort.Strings(newSubset)
				entry.Subsets[timestamp] = newSubset
			}
		}

		// Store updated data
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(domain), data)
	})
}

// countDomains calculates the total number of unique domains
func countDomains(subsets map[int64][]string) int {
	unique := make(map[string]struct{})
	for _, domains := range subsets {
		for _, d := range domains {
			unique[d] = struct{}{}
		}
	}
	return len(unique)
}

// printDomainsOnly prints just the domain names from all subsets
func printDomainsOnly(subsets map[int64][]string) {
	unique := make(map[string]struct{})
	for _, domains := range subsets {
		for _, d := range domains {
			unique[d] = struct{}{}
		}
	}
	sorted := make([]string, 0, len(unique))
	for d := range unique {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)
	for _, d := range sorted {
		fmt.Println(d)
	}
}

// printDomainsWithSubsetTimestamps prints domains grouped by fetch timestamp, newest first
func printDomainsWithSubsetTimestamps(subsets map[int64][]string) {
	type subset struct {
		Timestamp int64
		Domains   []string
	}
	sortedSubsets := make([]subset, 0, len(subsets))
	for ts, domains := range subsets {
		sortedSubsets = append(sortedSubsets, subset{Timestamp: ts, Domains: domains})
	}
	sort.Slice(sortedSubsets, func(i, j int) bool {
		return sortedSubsets[i].Timestamp > sortedSubsets[j].Timestamp // Descending order
	})

	for _, s := range sortedSubsets {
		fmt.Printf("Fetched at %s:\n", time.Unix(s.Timestamp, 0).Format(time.RFC3339))
		for _, d := range s.Domains {
			fmt.Printf("  %s\n", d)
		}
	}
}
