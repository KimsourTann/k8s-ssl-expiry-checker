package checker

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
	whois_parser "github.com/likexian/whois-parser"
	"golang.org/x/net/publicsuffix"
	networkingv1 "k8s.io/api/networking/v1"
)

var (
	whoisSem   = make(chan struct{}, 2)     // Throttle to 2 concurrent WHOIS lookups
	whoisCache = make(map[string]time.Time) // Cache domain -> expiry
	whoisLock  = sync.Mutex{}               // Lock to protect cache access
)

func GetAllIngressHosts(ingresses []networkingv1.Ingress) []string {
	hostSet := make(map[string]struct{})
	for _, ing := range ingresses {
		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if host != "" {
				hostSet[host] = struct{}{}
			}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	return hosts
}

func IsDomainWildcard(domain string) bool {
	return strings.Contains(domain, "*.")
}

func IsDomainReachable(domain string) bool {
	domain = strings.Replace(domain, "*.", "", 1)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + domain)

	if err != nil {
		return false
	}

	defer resp.Body.Close()
	return resp.StatusCode < 500 // you could also check for 200

}

func GetDomainExpiry(domain string) (time.Time, error) {
	if strings.HasPrefix(domain, "*.") {
		return time.Time{}, fmt.Errorf("skipping wildcard domain: %s", domain)
	}

	// Retry logic with exponential backoff
	var result string
	var err error

	maxRetriesStr := os.Getenv("MAX_RETRY")
	maxRetries, err := strconv.Atoi(maxRetriesStr)
	if err != nil {
		log.Fatalf("Invalid MAX_RETRY: %v", err)
		maxRetries = 1
	}
	// maxRetries := int(os.Getenv("DAY_TO_CHECK_EXPIRY"))
	// maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		result, err = whois.Whois(domain)
		if err == nil {
			break
		}

		// Retry only on network-related errors
		if strings.Contains(err.Error(), "connection reset by peer") ||
			strings.Contains(err.Error(), "timeout") {
			wait := time.Duration(1<<i) * time.Second // 1s, 2s, 4s
			fmt.Printf("Retrying %s after error: %v (wait %s)\n", domain, err, wait)
			time.Sleep(wait)
			continue
		}
		break
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("whois lookup failed after retries for %s: %w", domain, err)
	}

	// Parse WHOIS result
	parsed, err := whois_parser.Parse(result)
	if err != nil {
		if strings.Contains(err.Error(), "domain is not found") {
			return time.Time{}, fmt.Errorf("domain not found: %s", domain)
		}
		return time.Time{}, fmt.Errorf("whois parse error for %s: %w", domain, err)
	}

	expiryStr := parsed.Domain.ExpirationDate
	if expiryStr == "" {
		return time.Time{}, fmt.Errorf("expiry not found for domain: %s", domain)
	}

	// Date format layouts to try
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05", // Added format
		"2006-01-02",
		"2006.01.02",
		"02-Jan-2006",
		"2006/01/02",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, expiryStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse domain expiry for %s: %s", domain, expiryStr)
}

// GetRegistrableDomain extracts the root domain for WHOIS
func GetRegistrableDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

func GetCachedDomainExpiry(domain string) (time.Time, error) {
	whoisLock.Lock()
	expiry, ok := whoisCache[domain]
	whoisLock.Unlock()

	if ok {
		// println("Cached: ", domain)
		return expiry, nil
	}

	whoisSem <- struct{}{}
	expiry, err := GetDomainExpiry(domain)
	<-whoisSem

	if err == nil {
		whoisLock.Lock()
		whoisCache[domain] = expiry
		whoisLock.Unlock()
	}

	return expiry, err
}
