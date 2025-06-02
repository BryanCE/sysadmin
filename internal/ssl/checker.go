package ssl

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// CertInfo contains SSL certificate details
type CertInfo struct {
	Domain       string
	Issuer       string
	CommonName   string
	DNSNames     []string
	NotBefore    time.Time
	NotAfter     time.Time
	ExpiresIn    int
	IsValid      bool
	SerialNumber string
	SignatureAlg string
}

// CheckCertificate validates an SSL certificate for a given domain
func CheckCertificate(domain string, port string) (*CertInfo, error) {
	address := net.JoinHostPort(domain, port)
	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true, // We'll validate manually
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates presented")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()
	expiresIn := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := &CertInfo{
		Domain:       domain,
		Issuer:       cert.Issuer.String(),
		CommonName:   cert.Subject.CommonName,
		DNSNames:     cert.DNSNames,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		ExpiresIn:    expiresIn,
		IsValid:      now.After(cert.NotBefore) && now.Before(cert.NotAfter),
		SerialNumber: cert.SerialNumber.String(),
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}

	return info, nil
}
