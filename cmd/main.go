package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"
	"io"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Function to verify SRV records for XMPP
func verifySRVRecords(domain string) (clientRecords []*net.SRV, serverRecords []*net.SRV, err error) {
	_, clientRecords, err = net.LookupSRV("_xmpp-client", "_tcp", domain)
	if err != nil {
		return nil, nil, err
	}

	_, serverRecords, err = net.LookupSRV("_xmpp-server", "_tcp", domain)
	if err != nil {
		return nil, nil, err
	}

	return clientRecords, serverRecords, nil
}

// Function to attempt TCP connection
func attemptTCPConnection(host string, port string) (bool, string) {
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, "Connection failed"
	}
	defer conn.Close()
	return true, "Connection successful"
}

// Function to check TLS handshake
func checkTLSHandshake(host string, port string) (bool, string) {
	address := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, &tls.Config{
		// InsecureSkipVerify is set to false to ensure TLS certificates are verified
		InsecureSkipVerify: false,
	})
	if err != nil {
		return false, "TLS handshake failed: " + err.Error()
	}
	defer conn.Close()
	return true, "TLS handshake successful"
}

// Initialize Prometheus metrics
var (
	tcpConnectionFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tcp_connection_failures_total",
			Help: "Total number of TCP connection failures.",
		},
	)
	tlsHandshakeFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tls_handshake_failures_total",
			Help: "Total number of TLS handshake failures.",
		},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(tcpConnectionFailures)
	prometheus.MustRegister(tlsHandshakeFailures)
}

// Refactored checkXMPPConnectivity with dynamic error logging and metrics
func checkXMPPConnectivity(domain string) (bool, string) {
	clientRecords, serverRecords, err := verifySRVRecords(domain)
	if (err != nil) {
		log.Printf("SRV record lookup failed for domain %s: %v", domain, err)
		return false, "SRV record lookup failed"
	}

	var (
		result  string
		success = true
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	processRecord := func(recordType string, sr *net.SRV) {
		defer wg.Done()

		// Attempt TCP connection
		ok, msg := attemptTCPConnection(sr.Target, fmt.Sprintf("%d", sr.Port))
		mu.Lock()
		result += fmt.Sprintf("%s %s:%d - %s<br>", recordType, sr.Target, sr.Port, msg)
		if !ok {
			log.Printf("TCP connection failed for %s:%d - %s", sr.Target, sr.Port, msg)
			tcpConnectionFailures.Inc()
			success = false
		}
		mu.Unlock()

		// Perform TLS handshake
		okTLS, msgTLS := checkTLSHandshake(sr.Target, fmt.Sprintf("%d", sr.Port))
		mu.Lock()
		result += fmt.Sprintf("TLS %s:%d - %s<br>", sr.Target, sr.Port, msgTLS)
		if !okTLS {
			log.Printf("TLS handshake failed for %s:%d - %s", sr.Target, sr.Port, msgTLS)
			tlsHandshakeFailures.Inc()
			success = false
		}
		mu.Unlock()
	}

	// Launch goroutines for client records
	for _, sr := range clientRecords {
		wg.Add(1)
		go processRecord("Client", sr)
	}

	// Launch goroutines for server records
	for _, sr := range serverRecords {
		wg.Add(1)
		go processRecord("Server", sr)
	}

	// Wait for all checks to complete
	wg.Wait()

	if success {
		return true, "All connectivity checks passed.<br>" + result
	}
	return false, "Some connectivity checks failed.<br>" + result
}

// Struct to hold crawl results
type CrawlResult struct {
	Domain      string
	IsReachable bool
	Message     string
}

var results []CrawlResult
var mu sync.Mutex

// Updated crawlHandler to use the new connectivity checker
func crawlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get the domain from the form
		r.ParseForm()
		domain := r.FormValue("domain")

		// Check the XMPP service connectivity
		isReachable, message := checkXMPPConnectivity(domain)

		// Store the result in the shared results slice
		mu.Lock()
		results = append(results, CrawlResult{
			Domain:      domain,
			IsReachable: isReachable,
			Message:     message,
		})
		mu.Unlock()

		// Show the results to the user
		fmt.Fprintf(w, "<h1>Crawl Results</h1><p>%s: %s</p><p>%s</p>", domain, message, getResultsHTML())
	} else {
		// Display the form to enter a domain
		fmt.Fprintf(w, `
			<h1>Check XMPP Connectivity</h1>
			<form method="POST" action="/crawl">
				<label for="domain">Enter XMPP domain:</label>
				<input type="text" id="domain" name="domain" required>
				<input type="submit" value="Check">
			</form>
		`)
	}
}

// Helper function to display crawl results
func getResultsHTML() string {
	mu.Lock()
	defer mu.Unlock()

	var resultHTML string
	for _, result := range results {
		resultHTML += fmt.Sprintf("<p><b>%s:</b> %s - %t</p>", result.Domain, result.Message, result.IsReachable)
	}
	return resultHTML
}

// Struct to hold server information
type Server struct {
	ID          int    `json:"id"`
	Domain      string `json:"domain"`
	Description string `json:"description"`
	Features    string `json:"features"`
	Status      string `json:"status"`
}

var db *sql.DB

// Initialize the database
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "xmpp_directory.db")
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	query := `CREATE TABLE IF NOT EXISTS servers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		description TEXT,
		features TEXT,
		status TEXT NOT NULL
	)`
	if _, err := db.Exec(query); err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

// List servers from the database
func listServers(w http.ResponseWriter) {
	rows, err := db.Query("SELECT id, domain, description, features, status FROM servers")
	if err != nil {
		http.Error(w, "Failed to fetch servers", http.StatusInternalServerError)
		log.Printf("Failed to fetch servers: %v", err)
		return
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var s Server
		if err := rows.Scan(&s.ID, &s.Domain, &s.Description, &s.Features, &s.Status); err != nil {
			http.Error(w, "Failed to parse server data", http.StatusInternalServerError)
			log.Printf("Failed to parse server data: %v", err)
			return
		}
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(servers); err != nil {
		http.Error(w, "Failed to encode servers", http.StatusInternalServerError)
		log.Printf("Failed to encode servers: %v", err)
	}
}

// Function to validate server input
func validateServer(s Server) error {
	if s.Domain == "" {
		return errors.New("domain is required")
	}
	if s.Status == "" {
		return errors.New("status is required")
	}
	// Validate domain format using regex
	domainRegex := `^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(domainRegex, s.Domain)
	if err != nil {
		return fmt.Errorf("error validating domain: %v", err)
	}
	if !matched {
		return errors.New("invalid domain format")
	}
	// Add more validation as needed
	return nil
}

// Function to add a new server to the database using prepared statements
func addServer(w http.ResponseWriter, r *http.Request) {
    var s Server
    if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
        http.Error(w, "Invalid input", http.StatusBadRequest)
        log.Printf("Failed to decode request body: %v", err)
        return
    }

    // Check XMPP connectivity
    success, message := checkXMPPConnectivity(s.Domain)
    if !success {
        http.Error(w, "Server checks failed: "+message, http.StatusBadRequest)
        log.Printf("Connectivity check failed for domain %s: %s", s.Domain, message)
        return
    }

    // Use prepared statement to prevent SQL injection
    stmt, err := db.Prepare("INSERT INTO servers (domain, description, features, status) VALUES (?, ?, ?, ?)")
    if err != nil {
        http.Error(w, "Failed to prepare statement", http.StatusInternalServerError)
        log.Printf("Failed to prepare insert statement: %v", err)
        return
    }
    defer stmt.Close()

    result, err := stmt.Exec(s.Domain, s.Description, s.Features, s.Status)
    if err != nil {
        http.Error(w, "Failed to add server", http.StatusInternalServerError)
        log.Printf("Failed to execute insert statement: %v", err)
        return
    }

    id, err := result.LastInsertId()
    if err != nil {
        http.Error(w, "Failed to retrieve server ID", http.StatusInternalServerError)
        log.Printf("Failed to get last insert ID: %v", err)
        return
    }

    s.ID = int(id)
    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(s); err != nil {
        http.Error(w, "Failed to encode response", http.StatusInternalServerError)
        log.Printf("Failed to encode server response: %v", err)
    }
}

// Function to update an existing server in the database using prepared statements
func updateServer(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		log.Println("Update server request missing ID")
		return
	}

	serverID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		log.Printf("Invalid ID format: %s", id)
		return
	}

	var s Server
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		log.Printf("Failed to decode update request body: %v", err)
		return
	}

	if err := validateServer(s); err != nil {
		http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusBadRequest)
		log.Printf("Validation error for server ID %d: %v", serverID, err)
		return
	}

	// Use prepared statement to prevent SQL injection
	stmt, err := db.Prepare("UPDATE servers SET domain = ?, description = ?, features = ?, status = ? WHERE id = ?")
	if err != nil {
		http.Error(w, "Failed to prepare statement", http.StatusInternalServerError)
		log.Printf("Failed to prepare update statement: %v", err)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(s.Domain, s.Description, s.Features, s.Status, id)
	if err != nil {
		http.Error(w, "Failed to update server", http.StatusInternalServerError)
		log.Printf("Failed to execute update statement: %v", err)
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		http.Error(w, "Failed to retrieve affected rows", http.StatusInternalServerError)
		log.Printf("Failed to get rows affected: %v", err)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "No server found with the provided ID", http.StatusNotFound)
		log.Printf("No server found with ID %s to update", id)
		return
	}

	fmt.Fprintln(w, "Server updated successfully")
	log.Printf("Server with ID %s updated successfully", id)
}

// Delete a server from the database
func deleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		log.Println("Delete server request missing ID")
		return
	}

	serverID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		log.Printf("Invalid ID format for deletion: %s", id)
		return
	}

	query := `DELETE FROM servers WHERE id = ?`
	result, err := db.Exec(query, serverID)
	if err != nil {
		http.Error(w, "Failed to delete server", http.StatusInternalServerError)
		log.Printf("Failed to delete server with ID %d: %v", serverID, err)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Failed to retrieve affected rows", http.StatusInternalServerError)
		log.Printf("Failed to get rows affected for deletion: %v", err)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "No server found with the provided ID", http.StatusNotFound)
		log.Printf("No server found with ID %d to delete", serverID)
		return
	}

	fmt.Fprintln(w, "Server deleted successfully")
	log.Printf("Server with ID %d deleted successfully", serverID)
}

// Handler to display the add server form
func addServerForm(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, `
        <h1>Add New Server</h1>
        <form method="POST" action="/servers/add">
            <label for="domain">Domain:</label>
            <input type="text" id="domain" name="domain" required><br>
            <label for="description">Description:</label>
            <input type="text" id="description" name="description"><br>
            <label for="features">Features:</label>
            <input type="text" id="features" name="features"><br>
            <label for="status">Status:</label>
            <input type="text" id="status" name="status" required><br>
            <input type="submit" value="Add Server">
        </form>
    `)
}

// Handler to process the add server form
func addServerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Limit the size of the request body to prevent abuse
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
		defer r.Body.Close()

		var s Server
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			if errors.Is(err, io.EOF) {
				http.Error(w, "Request body cannot be empty", http.StatusBadRequest)
			} else {
				http.Error(w, "Invalid input", http.StatusBadRequest)
			}
			log.Printf("Failed to decode request body: %v", err)
			return
		}

		// Perform input validation
		if err := validateServer(s); err != nil {
			http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusBadRequest)
			log.Printf("Validation error for domain %s: %v", s.Domain, err)
			return
		}

		// Perform ping and XMPP checks
		isReachable, message := checkXMPPConnectivity(s.Domain)
		if !isReachable {
			http.Error(w, "Server checks failed: "+message, http.StatusBadRequest)
			log.Printf("Connectivity check failed for domain %s: %s", s.Domain, message)
			return
		}

		// Insert into database
		query := `INSERT INTO servers (domain, description, features, status) VALUES (?, ?, ?, ?)`
		result, err := db.Exec(query, s.Domain, s.Description, s.Features, s.Status)
		if err != nil {
			http.Error(w, "Failed to add server", http.StatusInternalServerError)
			log.Printf("Failed to add server: %v", err)
			return
		}

		id, err := result.LastInsertId()
		if err != nil {
			http.Error(w, "Failed to retrieve server ID", http.StatusInternalServerError)
			log.Printf("Failed to get last insert ID: %v", err)
			return
		}

		s.ID = int(id)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(s); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			log.Printf("Failed to encode server response: %v", err)
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		log.Printf("Method %s not allowed on /servers/add", r.Method)
	}
}

// Function to gracefully shutdown the server
func main() {
	initDB()
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	server := &http.Server{Addr: ":8080"}

	// Add Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/crawl", crawlHandler)
	http.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listServers(w)
		case http.MethodPost:
			addServerHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			log.Printf("Method %s not allowed on /servers", r.Method)
		}
	})
	http.HandleFunc("/servers/update", updateServer)
	http.HandleFunc("/servers/delete", deleteServer)

	// Add routes for the add server form
	http.HandleFunc("/servers/new", addServerForm)
	http.HandleFunc("/servers/add", addServerHandler)

	// Channel to listen for interrupt or terminate signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("Server started at http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Block until a signal is received.
	<-stop

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Println("Server gracefully stopped")
}
