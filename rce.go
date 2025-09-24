// Copyright 2017-2023 Block, Inc.

package rce

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
)

// TLSFiles represents the TLS files necessary to create a tls.Config.
// DEPRECATED: Use TLSConfig struct instead for better flexibility.
type TLSFiles struct {
	CACert string
	Cert   string
	Key    string
	OrgID  string
}

// TLSData represents TLS configuration that can handle both file paths and direct PEM content.
type TLSData struct {
	// CA certificate (root CA) - can be file path or PEM content
	CACert string
	// Client/Server certificate - can be file path or PEM content
	Cert string
	// Private key - can be file path or PEM content
	Key string
	// Organization ID for validation
	OrgID string
	// Set to true if the above fields contain PEM content instead of file paths
	IsPEMContent bool
}

// TLSConfig returns a new tls.Config with intermediate CA support and org validation.
// This method can handle both file paths and direct PEM content.
func (d TLSData) TLSConfig() (*tls.Config, error) {
	// If all fields empty, then no TLS config
	if d.CACert == "" && d.Cert == "" && d.Key == "" {
		return nil, nil
	}

	// If any field is given, all must be given
	switch {
	case d.CACert == "":
		return nil, fmt.Errorf("CA certificate not specified")
	case d.Cert == "":
		return nil, fmt.Errorf("Client certificate not specified")
	case d.Key == "":
		return nil, fmt.Errorf("Client key not specified")
	}

	// Load ROOT CA cert
	caCertData, err := loadCertData(d.CACert, d.IsPEMContent)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertData) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load certificate and key data
	certData, err := loadCertData(d.Cert, d.IsPEMContent)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	keyData, err := loadCertData(d.Key, d.IsPEMContent)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}

	// Parse certificate and key
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate and key: %v", err)
	}

	// Build tls.Config suitable for both client and server side
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,                     // client uses to verify server
		ClientCAs:    caCertPool,                     // server uses to verify client
		ClientAuth:   tls.RequireAndVerifyClientCert, // server must verify client cert
		Certificates: []tls.Certificate{cert},        // client/server cert (given to other side of connection)
	}

	// Add org validation if OrgID is specified
	if d.OrgID != "" {
		tlsConfig.VerifyPeerCertificate = createOrgValidator(d.OrgID)
	}

	tlsConfig.BuildNameToCertificate() // maps CommonName and SubjectAlternateName to cert

	return tlsConfig, nil
}

// ToTLSData converts TLSFiles to the new TLSData format for backward compatibility
func (f TLSFiles) ToTLSData() TLSData {
	return TLSData{
		CACert:       f.CACert,
		Cert:         f.Cert,
		Key:          f.Key,
		OrgID:        f.OrgID,
		IsPEMContent: false, // TLSFiles assumes file paths
	}
}

// isPEMContent checks if a string looks like PEM content rather than a file path
func isPEMContent(content string) bool {
	trimmed := strings.TrimSpace(content)
	return strings.HasPrefix(trimmed, "-----BEGIN") && strings.Contains(trimmed, "-----END")
}

// loadCertData loads certificate data from either a file path or direct PEM content
func loadCertData(data string, forcePEM bool) ([]byte, error) {
	if forcePEM || isPEMContent(data) {
		// Direct PEM content
		return []byte(data), nil
	}

	// File path
	content, err := ioutil.ReadFile(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", data, err)
	}
	return content, nil
}

// createOrgValidator returns a certificate validation function that ensures the peer certificate belongs to the specified organization
func createOrgValidator(expectedOrgID string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			return fmt.Errorf("no verified certificate chains")
		}

		// Get the leaf certificate (first in the chain)
		leafCert := verifiedChains[0][0]

		// Check Subject Organization
		for _, org := range leafCert.Subject.Organization {
			if strings.EqualFold(org, expectedOrgID) {
				return nil // Valid org found
			}
		}

		// Check Subject Common Name for org ID
		if strings.Contains(strings.ToLower(leafCert.Subject.CommonName), strings.ToLower(expectedOrgID)) {
			return nil
		}

		// Check Subject Alternative Names for org ID
		for _, san := range leafCert.DNSNames {
			if strings.Contains(strings.ToLower(san), strings.ToLower(expectedOrgID)) {
				return nil
			}
		}

		return fmt.Errorf("certificate does not belong to organization %s", expectedOrgID)
	}
}
