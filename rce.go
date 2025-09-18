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
type TLSFiles struct {
	CACert string
	Cert   string
	Key    string
	OrgID  string
}

// TLSConfig returns a new tls.Config with intermediate CA support and org validation.
func (f TLSFiles) TLSConfig() (*tls.Config, error) {
	// If all files empty, then no TLS config
	if f.CACert == "" && f.Cert == "" && f.Key == "" {
		return nil, nil
	}

	// If any file is given, all must be given
	switch {
	case f.CACert == "":
		return nil, fmt.Errorf("CA certificate file not specified")
	case f.Cert == "":
		return nil, fmt.Errorf("Client certificate file not specified")
	case f.Key == "":
		return nil, fmt.Errorf("Client key file not specified")
	}

	// Load ROOT CA cert
	caCert, err := ioutil.ReadFile(f.CACert)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", f.CACert)
	}

	// Load certificate chain (leaf + intermediate) and private key
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, fmt.Errorf("tls.LoadX509KeyPair %s %s: %s", f.Cert, f.Key, err)
	}

	// Build tls.Config suitable for both client and server side
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,                     // client uses to verify server
		ClientCAs:    caCertPool,                     // server uses to verify client
		ClientAuth:   tls.RequireAndVerifyClientCert, // server must verify client cert
		Certificates: []tls.Certificate{cert},        // client/server cert (given to other side of connection)
	}

	// Add org validation if OrgID is specified
	if f.OrgID != "" {
		tlsConfig.VerifyPeerCertificate = createOrgValidator(f.OrgID)
	}

	tlsConfig.BuildNameToCertificate() // maps CommonName and SubjectAlternateName to cert

	return tlsConfig, nil
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
