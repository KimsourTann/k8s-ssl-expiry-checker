package checker

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/KimsourTann/k8s-ssl-expiry-checker/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Run() error {
	dayToCheckExpiryStr := os.Getenv("DAY_TO_CHECK_EXPIRY")
	limitDayToCheckStr := os.Getenv("LIMIT_DAY_TO_CHECK")
	println(dayToCheckExpiryStr)
	println(limitDayToCheckStr)

	dayToCheckExpiry, err := strconv.Atoi(dayToCheckExpiryStr)
	if err != nil {
		fmt.Printf("Invalid DAY_TO_CHECK_EXPIRY value '%s': %v\n", dayToCheckExpiryStr, err)
		dayToCheckExpiry = 5
	}
	limitDayToCheck, err := strconv.Atoi(limitDayToCheckStr)
	if err != nil {
		fmt.Printf("Invalid LIMIT_DAY_TO_CHECK value '%s': %v\n", limitDayToCheckStr, err)
		limitDayToCheck = -5
	}

	fmt.Println("🔄 Starting SSL Check")

	clientset, err := internal.GetKubeClient()
	if err != nil {
		return fmt.Errorf("❌ Unable to create Kubernetes client: %w", err)
	}

	secrets, err := clientset.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("❌ Unable to list secrets: %w", err)
	}

	ingressList, err := clientset.NetworkingV1().Ingresses("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("❌ Unable to list ingresses: %w", err)
	}

	var wg sync.WaitGroup
	ch := make(chan DomainInfo, len(secrets.Items)+len(ingressList.Items))
	sem := make(chan struct{}, 20) // Limit concurrency to 10 goroutines
	// seenDomains := make(map[string]bool)
	// seenDomainsLock := &sync.Mutex{}
	// 🔍 Process secrets concurrently
	start := time.Now()
	fmt.Printf("🔍 Start checking at %s\n", start.Format(time.RFC3339))
	for _, secret := range secrets.Items {
		if secret.Type != "kubernetes.io/tls" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(secretName string, secretNamespace string, certData []byte) {
			defer wg.Done()
			defer func() { <-sem }()

			domain, err := GetDomainsFromCert(certData)
			// println("Domain %s", domain)
			if err != nil {
				fmt.Printf("GetDomainsFromCert secret %s/%s: %v\n", secretNamespace, secretName, err)
				return
			}

			// seenDomainsLock.Lock()
			// if seenDomains[domain] {
			// 	seenDomainsLock.Unlock()
			// 	return // Skip if already seen
			// }
			// seenDomains[domain] = true
			// seenDomainsLock.Unlock()

			info := DomainInfo{
				Domain:    domain,
				Namespace: secretNamespace,
				Secret:    secretName,
			}

			expiry, err := ParseCertExpiry(certData)
			if err != nil {
				fmt.Printf("ParseCertExpiry secret %s/%s: %v\n", secretNamespace, secretName, err)
				return
			}
			sslExpiredIn := int(time.Until(expiry).Hours() / 24)
			isSSLExpiry := sslExpiredIn <= dayToCheckExpiry && sslExpiredIn > limitDayToCheck

			if isSSLExpiry {
				info.ExpiresInDays = sslExpiredIn
				info.IsSSLExpiry = isSSLExpiry
				info.ExpiryTime = expiry
			}

			rootDomain, err := GetRegistrableDomain(domain)
			if err != nil {
				fmt.Printf("GetRegistrableDomain secret %s/%s: %v\n", secretNamespace, secretName, err)
				return
			}

			// domainExpiry, err := GetDomainExpiry(rootDomain)
			domainExpiry, err := GetCachedDomainExpiry(rootDomain)
			if err != nil {
				fmt.Printf("GetCachedDomainExpiry secret %s/%s: %v\n", secretNamespace, secretName, err)
				return
			}

			domainExpiresIn := int(time.Until(domainExpiry).Hours() / 24)
			isDomainExpiry := domainExpiresIn <= dayToCheckExpiry && domainExpiresIn > limitDayToCheck

			if isDomainExpiry {
				info.DomainExpiresIn = domainExpiresIn
				info.IsDomainExpiry = isDomainExpiry
				info.DomainExpiryTime = domainExpiry
			}

			var ingressNames []string
			for _, ing := range ingressList.Items {
				for _, tls := range ing.Spec.TLS {
					if tls.SecretName == secretName && ing.Namespace == secretNamespace {
						ingressNames = append(ingressNames, ing.Name)
					}
				}
			}
			info.Ingresses = ingressNames

			ch <- info
		}(secret.Name, secret.Namespace, secret.Data["tls.crt"])
	}

	// 🔍 Process ingress hosts concurrently
	for _, ing := range ingressList.Items {
		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if host == "" || IsDomainWildcard(host) {
				continue
			}

			// ✅ Skip if not using HTTPS (not in .spec.tls)
			// isHTTPS := false
			// for _, tls := range ing.Spec.TLS {
			// 	for _, tlsHost := range tls.Hosts {
			// 		if tlsHost == host {
			// 			isHTTPS = true
			// 			break
			// 		}
			// 	}
			// 	if isHTTPS {
			// 		break
			// 	}
			// }
			// if !isHTTPS {
			// 	continue
			// }

			wg.Add(1)
			sem <- struct{}{}
			go func(host, namespace, ingressName string) {
				defer wg.Done()
				defer func() { <-sem }()

				// seenDomainsLock.Lock()
				// if seenDomains[host] {
				// 	seenDomainsLock.Unlock()
				// 	return // Skip if already seen
				// }
				// seenDomains[host] = true
				// seenDomainsLock.Unlock()

				info := DomainInfo{
					Domain:    host,
					Namespace: namespace,
					Ingresses: []string{ingressName},
				}

				expiry, err := GetSSLCertExpiry(host)
				if err != nil {
					fmt.Printf("GetSSLCertExpiry ingress  %s: %v\n", host, err)
					return
				}

				sslExpiredIn := int(time.Until(expiry).Hours() / 24)
				isSSLExpiry := sslExpiredIn <= dayToCheckExpiry && sslExpiredIn > limitDayToCheck

				if isSSLExpiry {
					info.ExpiresInDays = sslExpiredIn
					info.IsSSLExpiry = isSSLExpiry
					info.ExpiryTime = expiry
				}

				rootDomain, err := GetRegistrableDomain(host)
				if err != nil {
					fmt.Printf("GetRegistrableDomain ingress %s/%s: %v\n", namespace, ingressName, err)
					return
				}

				domainExpiry, err := GetCachedDomainExpiry(rootDomain)
				if err != nil {
					fmt.Printf("GetCachedDomainExpiry ingress %s/%s: %v\n", namespace, ingressName, err)
					return
				}

				domainExpiresIn := int(time.Until(domainExpiry).Hours() / 24)
				isDomainExpiry := domainExpiresIn <= dayToCheckExpiry && domainExpiresIn > limitDayToCheck

				if isDomainExpiry {
					info.DomainExpiresIn = domainExpiresIn
					info.IsDomainExpiry = isDomainExpiry
					info.DomainExpiryTime = domainExpiry
				}

				ch <- info
			}(host, ing.Namespace, ing.Name)
		}
	}
	// ✅ Wait for all goroutines to complete
	wg.Wait()
	close(ch)
	end := time.Now()
	fmt.Printf("✅ Done  checking at %s (Duration: %s)\n", end.Format(time.RFC3339), end.Sub(start))

	// ✅ Collect results
	var unreachable []DomainInfo
	var expiringSoon []DomainInfo

	for info := range ch {

		if info.IsDomainExpiry || info.IsSSLExpiry {
			if IsDomainWildcard(info.Domain) || IsDomainReachable(info.Domain) {
				expiringSoon = append(expiringSoon, info)
			} else {
				unreachable = append(unreachable, info)
			}
		}
	}

	// 📨 Final report
	message := FormatReport(unreachable, expiringSoon)
	fmt.Println(message)

	SendTelegram(message)

	return nil
}
