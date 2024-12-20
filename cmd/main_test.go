package main

import (
	"fmt"
	"net"
	"testing"
)

// Mock function definitions
var lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
	return "", nil, nil
}

var mockAttemptTCPConnection = func(host string, port string) (bool, string) {
	return false, "Not implemented"
}

var mockCheckTLSHandshake = func(host string, port string) (bool, string) {
	return false, "Not implemented"
}

// Mock function definitions


// Mock functions to replace actual network calls
var (
	originalLookupSRV         = lookupSRV
	originalAttemptTCP        = mockAttemptTCPConnection
	originalCheckTLSHandshake = mockCheckTLSHandshake
)

// restoreMocks restores the original functions after tests
func restoreMocks() {
	lookupSRV = originalLookupSRV
	mockAttemptTCPConnection = originalAttemptTCP
	mockCheckTLSHandshake = originalCheckTLSHandshake
}

// TestCheckXMPPConnectivitySuccess tests successful XMPP connectivity.
func TestCheckXMPPConnectivitySuccess(t *testing.T) {
	defer restoreMocks()

	lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{
				Target: "xmpp-client.example.com.",
				Port:   5269,
			},
			{
				Target: "xmpp-server.example.com.",
				Port:   5269,
			},
		}, nil
	}

	mockAttemptTCPConnection = func(host string, port string) (bool, string) {
		return true, "Connection successful"
	}

	mockCheckTLSHandshake = func(host string, port string) (bool, string) {
		return true, "TLS handshake successful"
	}

	success, message := checkXMPPConnectivity("example.com")
	if !success {
		t.Errorf("Expected connectivity to pass, but got failure: %s", message)
	}
}

// TestCheckXMPPConnectivityFailure tests failed XMPP connectivity due to SRV lookup failure.
func TestCheckXMPPConnectivityFailure(t *testing.T) {
	defer restoreMocks()

	lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		return "", nil, fmt.Errorf("SRV lookup failed")
	}

	success, _ := checkXMPPConnectivity("invalid.com")
	if success {
		t.Errorf("Expected connectivity to fail, but it passed")
	}
}

// TestCheckXMPPConnectivityPartialFailure tests partial failures in connectivity checks.
func TestCheckXMPPConnectivityPartialFailure(t *testing.T) {
	defer restoreMocks()

	lookupSRV = func(service, proto, name string) (string, []*net.SRV, error) {
		return "", []*net.SRV{
			{
				Target: "xmpp-client.example.com.",
				Port:   5269,
			},
		}, nil
	}

	mockAttemptTCPConnection = func(host string, port string) (bool, string) {
		if host == "xmpp-client.example.com." {
			return true, "Connection successful"
		}
		return false, "Connection failed"
	}

	mockCheckTLSHandshake = func(host string, port string) (bool, string) {
		if host == "xmpp-client.example.com." {
			return true, "TLS handshake successful"
		}
		return false, "TLS handshake failed"
	}

	success, message := checkXMPPConnectivity("example.com")
	if success {
		t.Errorf("Expected connectivity to fail due to partial failures, but it passed: %s", message)
	}
}