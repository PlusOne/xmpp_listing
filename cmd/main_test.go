package main

import (
	"fmt"
	"net"
	"testing"
)

// DNSResolver defines an interface for DNS lookups, facilitating mocking.
type DNSResolver interface {
	LookupSRV(service, proto, name string) (string, []*net.SRV, error)
}

// Connector defines an interface for TCP connections, facilitating mocking.
type Connector interface {
	AttemptTCPConnection(host, port string) (bool, string)
	CheckTLSHandshake(host, port string) (bool, string)
}

// func (c *MockConnector) AttemptTCPConnection(param any, s string) (bool, string) {
// 	panic("unimplemented")
// }

// TestCheckXMPPConnectivitySuccess tests successful XMPP connectivity.
func TestCheckXMPPConnectivitySuccess(t *testing.T) {
	// Create mock resolver
	mockResolver := &MockResolver{
		LookupSRVFunc: func(service, proto, name string) (string, []*net.SRV, error) {
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
		},
	}

	// Create mock connector
	mockConnector := &MockConnector{
		AttemptTCPFunc: func(host, port string) (bool, string) {
			return true, "Connection successful"
		},
		CheckTLSFunc: func(host, port string) (bool, string) {
			return true, "TLS handshake successful"
		},
	}

	success, message := checkXMPPConnectivityWithMocks("example.com", mockResolver, mockConnector)
	if !success {
		t.Errorf("Expected connectivity to pass, but got failure: %s", message)
	}
}

// TestCheckXMPPConnectivityFailure tests failed XMPP connectivity due to SRV lookup failure.
func TestCheckXMPPConnectivityFailure(t *testing.T) {
	// Create mock resolver that fails
	mockResolver := &MockResolver{
		LookupSRVFunc: func(service, proto, name string) (string, []*net.SRV, error) {
			return "", nil, fmt.Errorf("SRV lookup failed")
		},
	}

	// Create mock connector (won't be called)
	mockConnector := &MockConnector{}

	success, _ := checkXMPPConnectivityWithMocks("invalid.com", mockResolver, mockConnector)
	if success {
		t.Errorf("Expected connectivity to fail, but it passed")
	}
}

// TestCheckXMPPConnectivityPartialFailure tests partial failures in connectivity checks.
func TestCheckXMPPConnectivityPartialFailure(t *testing.T) {
	// Create mock resolver with partial records
	mockResolver := &MockResolver{
		LookupSRVFunc: func(service, proto, name string) (string, []*net.SRV, error) {
			return "", []*net.SRV{
				{
					Target: "xmpp-client.example.com.",
					Port:   5269,
				},
			}, nil
		},
	}

	// Create mock connector with partial failures
	mockConnector := &MockConnector{
		AttemptTCPFunc: func(host, port string) (bool, string) {
			if host == "xmpp-client.example.com." {
				return true, "Connection successful"
			}
			return false, "Connection failed"
		},
		CheckTLSFunc: func(host, port string) (bool, string) {
			if host == "xmpp-client.example.com." {
				return true, "TLS handshake successful"
			}
			return false, "TLS handshake failed"
		},
	}

	success, message := checkXMPPConnectivityWithMocks("example.com", mockResolver, mockConnector)
	if success {
		t.Errorf("Expected connectivity to fail due to partial failures, but it passed: %s", message)
	}
}

// MockResolver is a mock implementation of DNSResolver.
type MockResolver struct {
	LookupSRVFunc func(service, proto, name string) (string, []*net.SRV, error)
}

func (m *MockResolver) LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	return m.LookupSRVFunc(service, proto, name)
}

// MockConnector is a mock implementation of Connector.
type MockConnector struct {
	AttemptTCPFunc func(host, port string) (bool, string)
	CheckTLSFunc   func(host, port string) (bool, string)
}

func (m *MockConnector) AttemptTCPConnection(host, port string) (bool, string) {
	return m.AttemptTCPFunc(host, port)
}

func (m *MockConnector) CheckTLSHandshake(host, port string) (bool, string) {
	return m.CheckTLSFunc(host, port)
}

// checkXMPPConnectivityWithMocks allows injecting mocks for testing.
func checkXMPPConnectivityWithMocks(domain string, resolver DNSResolver, connector Connector) (bool, string) {
	_, clientRecords, err := resolver.LookupSRV("_xmpp-client", "_tcp", domain)
	if err != nil {
		return false, "SRV record lookup failed: " + err.Error()
	}

	_, serverRecords, srvErr := resolver.LookupSRV("_xmpp-server", "_tcp", domain)
	if srvErr != nil {
		return false, "SRV record lookup failed: " + srvErr.Error()
	}

	var result string
	success := true

	// Check client connections
	for _, sr := range clientRecords {
		ok, msg := connector.AttemptTCPConnection(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("Client %s:%d - %s<br>", sr.Target, sr.Port, msg)
		if !ok {
			success = false
		}
		// Optional TLS check
		okTLS, msgTLS := connector.CheckTLSHandshake(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("TLS %s:%d - %s<br>", sr.Target, sr.Port, msgTLS)
		if !okTLS {
			success = false
		}
	}

	// Check server connections
	for _, sr := range serverRecords {
		ok, msg := connector.AttemptTCPConnection(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("Server %s:%d - %s<br>", sr.Target, sr.Port, msg)
		if !ok {
			success = false
		}
		// Optional TLS check
		okTLS, msgTLS := connector.CheckTLSHandshake(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("TLS %s:%d - %s<br>", sr.Target, sr.Port, msgTLS)
		if !okTLS {
			success = false
		}
	}

	if success {
		return true, "All connectivity checks passed.<br>" + result
	}
	return false, "Some connectivity checks failed.<br>" + result
}
