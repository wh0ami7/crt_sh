package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/errgroup"
)

// Constants
const (
	cacheFile        = "crtsh_cache.db"
	flowTimeout      = 120 * time.Second
	startConcurrency = 5
	baseRetryDelay   = 2 * time.Second
	shardCount       = 64
)

// Cert represents a crt.sh certificate entry
type Cert struct {
	NameValue string `json:"name_value"`
}

// CacheEntry stores domain subsets with timestamps
type CacheEntry struct {
	Domains     []string `json:"domains"`
	LastFetched int64    `json:"last_fetched"`
}

// Fetcher defines the interface for fetching domains
type Fetcher interface {
	Fetch(ctx context.Context, param, value string) ([]string, error)
}

// DomainStore defines the interface for storing domains
type DomainStore interface {
	Add(domain string) bool
	ToSlice() []string
}

// Config holds shared configuration
type Config struct {
	Timeout        time.Duration
	BaseRetryDelay time.Duration
	Verbose        bool
	Concurrency    int
}

// httpFetcher implements Fetcher for HTTP requests
type httpFetcher struct {
	client *http.Client
	config *Config
}

// NewHTTPFetcher creates a new httpFetcher
func NewHTTPFetcher(config *Config) Fetcher {
	return &httpFetcher{
		client: &http.Client{
			Transport: &http.Transport{
				MaxConnsPerHost: startConcurrency,
				IdleConnTimeout: 90 * time.Second,
			},
		},
		config: config,
	}
}

// Fetch retrieves domains with retries until success
func (f *httpFetcher) Fetch(ctx context.Context, param, value string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?%s=%%25.%s&output=json", param, value)
	attempt := 0

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			attempt++
			ctx, cancel := context.WithTimeout(ctx, f.config.Timeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, fmt.Errorf("request creation failed: %w", err)
			}

			resp, err := f.client.Do(req)
			if err != nil {
				if f.config.Verbose {
					fmt.Fprintf(os.Stderr, "%s attempt %d failed for %s: %v\n", param, attempt, value, err)
				}
				time.Sleep(retryBackoff(attempt, f.config.BaseRetryDelay))
				continue
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				reader := bufio.NewReader(resp.Body)
				decoder := json.NewDecoder(reader)
				var certs []Cert
				if err := decoder.Decode(&certs); err != nil {
					return nil, fmt.Errorf("decode failed: %w", err)
				}
				return extractDomains(certs, domain), nil
			case http.StatusTooManyRequests:
				delay := parseRetryAfter(resp)
				if delay == 0 {
					delay = retryBackoff(attempt, f.config.BaseRetryDelay)
				}
				f.config.Concurrency = max(f.config.Concurrency/2, 1)
				if f.config.Verbose {
					fmt.Fprintf(os.Stderr, "%s rate limited (429) for %s, attempt %d, concurrency now %d, waiting %v\n", param, value, attempt, f.config.Concurrency, delay)
				}
				time.Sleep(delay)
			case http.StatusBadGateway:
				delay := retryBackoff(attempt, f.config.BaseRetryDelay) * 2
				if f.config.Verbose {
					fmt.Fprintf(os.Stderr, "%s bad gateway (502) for %s, attempt %d, waiting %v\n", param, value, attempt, delay)
				}
				time.Sleep(delay)
			default:
				if f.config.Verbose {
					fmt.Fprintf(os.Stderr, "%s status %d for %s, attempt %d, retrying\n", param, resp.StatusCode, value, attempt)
				}
				time.Sleep(retryBackoff(attempt, f.config.BaseRetryDelay))
			}
		}
	}
}

// ShardedDomainStore implements DomainStore
type ShardedDomainStore struct {
	shards []struct {
		sync.RWMutex
		domains map[string]struct{}
	}
}

// NewShardedDomainStore creates a sharded store
func NewShardedDomainStore(shardCount int) *ShardedDomainStore {
	shards := make([]struct {
		sync.RWMutex
		domains map[string]struct{}
	}, shardCount)
	for i := range shards {
		shards[i].domains = make(map[string]struct{}, shardCount) // Pre-allocate
	}
	return &ShardedDomainStore{shards: shards}
}

// Add adds a domain, returning true if new
func (s *ShardedDomainStore) Add(domain string) bool {
	h := fnv.New32a()
	h.Write([]byte(domain))
	shardIdx := h.Sum32() % uint32(len(s.shards))
	shard := &s.shards[shardIdx]
	shard.Lock()
	defer shard.Unlock()
	if _, exists := shard.domains[domain]; exists {
		return false
	}
	shard.domains[domain] = struct{}{}
	return true
}

// ToSlice converts to a sorted slice
func (s *ShardedDomainStore) ToSlice() []string {
	var domains []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := range s.shards {
		wg.Add(1)
		go func(shard struct {
			sync.RWMutex
			domains map[string]struct{}
		}) {
			defer wg.Done()
			shard.RLock()
			defer shard.RUnlock()
			local := make([]string, 0, len(shard.domains))
			for d := range shard.domains {
				local = append(local, d)
			}
			mu.Lock()
			domains = append(domains, local...)
			mu.Unlock()
		}(s.shards[i])
	}
	wg.Wait()
	slices.Sort(domains)
	return slices.Compact(domains)
}

// CLI variables
var (
	domain    string
	verbose   bool
	fromCache bool
	config    = &Config{
		Timeout:        flowTimeout,
		BaseRetryDelay: baseRetryDelay,
		Concurrency:    startConcurrency,
	}
)

// rootCmd defines the CLI
var rootCmd = &cobra.Command{
	Use:   "crtsh",
	Short: "Fetch subdomains from crt.sh",
	Long:  "A tool for fetching subdomains from crt.sh with persistent caching.",
	RunE:  run,
}

func init() {
	rootCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to query (required)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.Flags().BoolVarP(&fromCache, "from-cache", "c", false, "Use cached data only")
	if err := rootCmd.MarkFlagRequired("domain"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set required flag: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run executes the main logic
func run(_ *cobra.Command, _ []string) error {
	domain = strings.ToLower(domain)
	config.Verbose = verbose
	if verbose {
		fmt.Printf("Querying %s (timeout: %v, initial concurrency: %d)\n", domain, config.Timeout, config.Concurrency)
	}

	db, err := bolt.Open(cacheFile, 0600, nil)
	if err != nil {
		return fmt.Errorf("database open failed: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		cancel()
	}()

	if fromCache {
		return displayCache(ctx, db)
	}

	return fetchAndStoreDomains(ctx, db)
}

// fetchAndStoreDomains fetches and stores domains
func fetchAndStoreDomains(ctx context.Context, db *bolt.DB) error {
	fetcher := NewHTTPFetcher(config)
	store := NewShardedDomainStore(shardCount)

	// Load existing caches
	rootCache, err := loadCacheBucket(db, "root_domains")
	if err != nil {
		return err
	}
	additionalCache, err := loadCacheBucket(db, "additional_domains")
	if err != nil {
		return err
	}

	// Populate store with existing data
	if rootCache != nil {
		for _, d := range rootCache.Domains {
			store.Add(d)
		}
	}
	if additionalCache != nil {
		for _, d := range additionalCache.Domains {
			store.Add(d)
		}
	}

	// Fetch root domains (first flow)
	rootDomains, err := fetcher.Fetch(ctx, "CN", domain)
	if err != nil {
		return fmt.Errorf("root domains fetch failed: %w", err)
	}
	if verbose {
		fmt.Printf("Root domains: %d found\n", len(rootDomains))
	}

	// Update store and persist root domains
	newRootCount := 0
	for _, d := range rootDomains {
		if store.Add(d) {
			newRootCount++
		}
	}
	if newRootCount > 0 {
		if err := saveCacheBucket(db, "root_domains", rootDomains, time.Now()); err != nil {
			return fmt.Errorf("root domains save failed: %w", err)
		}
	}

	// Second flow: parallel with sequential HTTP 200 await within workers
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, config.Concurrency)
	for i, root := range rootDomains {
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				domains, err := fetcher.Fetch(ctx, "q", root)
				if err != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Additional fetch failed for %s: %v\n", root, err)
					}
					return nil // Continue despite error
				}
				newCount := 0
				for _, d := range domains {
					if store.Add(d) {
						newCount++
					}
				}
				if verbose {
					fmt.Printf("Additional: Processed %d/%d, added %d for %s\n", i+1, len(rootDomains), newCount, root)
				}
				return saveCacheBucket(db, "additional_domains", domains, time.Now())
			}
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return saveCacheBucket(db, "combined_domains", store.ToSlice(), time.Now())
}

// extractDomains extracts domains from certificates
func extractDomains(certs []Cert, domain string) []string {
	re := regexp.MustCompile(`^(.+\.)*` + regexp.QuoteMeta(domain) + `$`)
	var domains []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, cert := range certs {
		wg.Add(1)
		go func(c Cert) {
			defer wg.Done()
			var local []string
			for _, line := range strings.Split(c.NameValue, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "*.") {
					lower = lower[2:]
				}
				if re.MatchString(lower) {
					local = append(local, lower)
				}
			}
			mu.Lock()
			domains = append(domains, local...)
			mu.Unlock()
		}(cert)
	}

	wg.Wait()
	slices.Sort(domains)
	return slices.Compact(domains)
}

// retryBackoff calculates exponential backoff with jitter
func retryBackoff(attempt int, base time.Duration) time.Duration {
	delay := base * time.Duration(1<<(attempt-1))
	jitter := time.Duration(rand.Int63n(int64(base)))
	return delay + jitter
}

// parseRetryAfter reads the Retry-After header
func parseRetryAfter(resp *http.Response) time.Duration {
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil {
			return time.Duration(seconds) * time.Second
		}
		if t, err := time.Parse(time.RFC1123, retryAfter); err == nil {
			return time.Until(t)
		}
	}
	return 0
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func loadCacheBucket(db *bolt.DB, bucketName string) (*CacheEntry, error) {
	var entry CacheEntry
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
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
		return nil, fmt.Errorf("load %s failed: %w", bucketName, err)
	}
	return &entry, nil
}

func saveCacheBucket(db *bolt.DB, bucketName string, domains []string, fetchTime time.Time) error {
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("create %s bucket failed: %w", bucketName, err)
		}

		entry := CacheEntry{
			Domains:     domains,
			LastFetched: fetchTime.Unix(),
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal %s failed: %w", bucketName, err)
		}
		return b.Put([]byte(domain), data)
	})
}

func displayCache(ctx context.Context, db *bolt.DB) error {
	combined, err := loadCacheBucket(db, "combined_domains")
	if err != nil {
		return err
	}
	if combined == nil || len(combined.Domains) == 0 {
		fmt.Println("No cached data for", domain)
		return nil
	}
	if verbose {
		fmt.Printf("Found %d domains in cache\n", len(combined.Domains))
	}
	for _, d := range combined.Domains {
		fmt.Println(d)
	}
	return nil
}

func printDomains(subsets map[int64][]string) {
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
	slices.Sort(sorted)
	for _, d := range sorted {
		fmt.Println(d)
	}
}

func printDomainsWithTimestamps(subsets map[int64][]string) {
	type subset struct {
		Timestamp int64
		Domains   []string
	}
	sorted := make([]subset, 0, len(subsets))
	for ts, domains := range subsets {
		sorted = append(sorted, subset{Timestamp: ts, Domains: domains})
	}
	slices.SortFunc(sorted, func(a, b subset) int {
		return int(b.Timestamp - a.Timestamp)
	})
	for _, s := range sorted {
		fmt.Printf("Fetched at %s:\n", time.Unix(s.Timestamp, 0).Format(time.RFC3339))
		for _, d := range s.Domains {
			fmt.Printf("  %s\n", d)
		}
	}
}
