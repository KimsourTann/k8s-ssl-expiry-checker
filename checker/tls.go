package checker

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

func ParseCertExpiry(pemBytes []byte) (time.Time, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return time.Time{}, fmt.Errorf("could not decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
func ParseCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var block *pem.Block
	rest := pemData

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found")
	}

	return certs, nil
}
func GetSSLCertExpiry(host string) (time.Time, error) {
	dialer := &net.Dialer{
		Timeout: 1 * time.Second,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificate found")
	}
	return certs[0].NotAfter, nil
}

func GetDomainsFromCert(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	var domains []string
	if len(cert.DNSNames) > 0 {
		domains = cert.DNSNames
	} else if cert.Subject.CommonName != "" {
		domains = []string{cert.Subject.CommonName}
	}

	if len(domains) == 0 {
		return "", fmt.Errorf("no domain names found in certificate")
	}

	return domains[0], nil
}
