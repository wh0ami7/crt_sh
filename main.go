package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Cert represents the structure of each JSON object from the crt.sh API response.
type Cert struct {
	NameValue string `json:"name_value"`
}

func main() {
	// Check for command-line argument
	if len(os.Args) < 2 {
		log.Fatal("Error: Domain required. Usage: go run crtsh.go domain.com")
	}
	domain := strings.ToLower(os.Args[1]) // Convert domain to lowercase for consistency

	// Construct the API URL
	url := fmt.Sprintf("https://crt.sh/?CN=%%25.%s&output=json", domain)

	// Make the HTTP GET request
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Verify HTTP status
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error: HTTP status %d", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Parse the JSON response
	var certs []Cert
	if err := json.Unmarshal(body, &certs); err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	// Compile regex pattern for domain matching
	domainPattern := regexp.MustCompile(`^(.+\.)*` + regexp.QuoteMeta(domain) + `$`)

	// Use a map to collect unique domains
	uniqueDomains := make(map[string]struct{})

	// Process each certificate entry
	for _, cert := range certs {
		// Split name_value by newlines as it may contain multiple domains
		lines := strings.Split(cert.NameValue, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue // Skip empty lines
			}
			// Convert to lowercase and process
			lowerLine := strings.ToLower(line)
			if domainPattern.MatchString(lowerLine) {
				// Remove wildcard prefix if present
				if strings.HasPrefix(lowerLine, "*.") {
					lowerLine = strings.TrimPrefix(lowerLine, "*.")
				}
				uniqueDomains[lowerLine] = struct{}{}
			}
		}
	}

	// Convert map keys to a slice for sorting
	var domains []string
	for domain := range uniqueDomains {
		domains = append(domains, domain)
	}

	// Sort the domains alphabetically
	sort.Strings(domains)

	// Output the results
	for _, domain := range domains {
		fmt.Println(domain)
	}
}
