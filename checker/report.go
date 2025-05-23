package checker

import (
	"fmt"
	"strings"
	"time"
)

type DomainInfo struct {
	Domain           string
	Namespace        string
	Secret           string
	Ingresses        []string
	ExpiresInDays    int       // SSL expiry days
	ExpiryTime       time.Time // SSL expiry time
	IsSSLExpiry      bool      // To control SSL expire or not
	DomainExpiresIn  int       // WHOIS expiry days
	DomainExpiryTime time.Time // WHOIS expiry time
	IsDomainExpiry   bool      // To control Domain expire or not
}

func FormatReport(unreachable []DomainInfo, expiringSoon []DomainInfo) string {
	var sb strings.Builder
	date := time.Now()
	sb.WriteString("🔍 SSL and Domain Expiry Report 📅\n\n")
	sb.WriteString(fmt.Sprintf("Date: %s\n", date.Format(time.RFC3339Nano)))
	sb.WriteString("---\n\n")

	// Unreachable
	sb.WriteString("❌ Domains Unreachable\n\n")
	for _, d := range unreachable {
		sb.WriteString(fmt.Sprintf("🔴 %s\n", d.Domain))
		sb.WriteString(fmt.Sprintf("  - 📍 Namespace: %s\n", d.Namespace))
		if d.Secret != "" {
			sb.WriteString(fmt.Sprintf("  - 🔑 Secret: %s\n", d.Secret))
		}
		if len(d.Ingresses) > 0 {
			if len(d.Ingresses) == 1 {
				sb.WriteString(fmt.Sprintf("  - 🚀 Ingress: %s\n", d.Ingresses[0]))
			} else {
				sb.WriteString("  - 🚀 Ingress: \n")
				for _, ing := range d.Ingresses {
					sb.WriteString(fmt.Sprintf("    - %s\n", ing))
				}
			}
		}
		sb.WriteString("\n\n")
	}

	// Expiring soon
	sb.WriteString("✅ Active Domains (Expiring Soon)\n\n")
	for _, d := range expiringSoon {
		if d.IsSSLExpiry || d.IsDomainExpiry {
			sb.WriteString(fmt.Sprintf("🟢 %s\n", d.Domain))
			sb.WriteString(fmt.Sprintf("  - 📍 Namespace: %s\n", d.Namespace))
			if d.Secret != "" {
				sb.WriteString(fmt.Sprintf("  - 🔑 Secret: %s\n", d.Secret))
			}
			if len(d.Ingresses) > 0 {
				if len(d.Ingresses) == 1 {
					sb.WriteString(fmt.Sprintf("  - 🚀 Ingress: %s\n", d.Ingresses[0]))
				} else {
					sb.WriteString("  - 🚀 Ingress: \n")
					for _, ing := range d.Ingresses {
						sb.WriteString(fmt.Sprintf("    - %s\n", ing))
					}
				}
			}

			if d.IsSSLExpiry {
				ict := d.ExpiryTime.In(time.FixedZone("ICT", 7*60*60))
				sb.WriteString(fmt.Sprintf("  - ⏳ SSL Expires in %d Days, Until (ICT - Phnom Penh): %s\n",
					d.ExpiresInDays, ict.Format("2006-01-02 15:04:05")))
			}

			if d.IsDomainExpiry {
				domainICT := d.DomainExpiryTime.In(time.FixedZone("ICT", 7*60*60))
				sb.WriteString(fmt.Sprintf("  - ⏳ Domain Expires in %d Days, Until (ICT - Phnom Penh): %s\n",
					d.DomainExpiresIn, domainICT.Format("2006-01-02 15:04:05")))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
