package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
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
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false, "TLS handshake failed"
	}
	defer conn.Close()
	return true, "TLS handshake successful"
}

// Updated checkXMPP to include SRV and TCP checks
func checkXMPPConnectivity(domain string) (bool, string) {
	clientRecords, serverRecords, err := verifySRVRecords(domain)
	if err != nil {
		return false, "SRV record lookup failed"
	}

	var result string
	success := true

	// Check client connections
	for _, sr := range clientRecords {
		ok, msg := attemptTCPConnection(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("Client %s:%d - %s<br>", sr.Target, sr.Port, msg)
		if !ok {
			success = false
		}
		// Optional TLS check
		okTLS, msgTLS := checkTLSHandshake(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("TLS %s:%d - %s<br>", sr.Target, sr.Port, msgTLS)
		if !okTLS {
			success = false
		}
	}

	// Check server connections
	for _, sr := range serverRecords {
		ok, msg := attemptTCPConnection(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("Server %s:%d - %s<br>", sr.Target, sr.Port, msg)
		if !ok {
			success = false
		}
		// Optional TLS check
		okTLS, msgTLS := checkTLSHandshake(sr.Target, fmt.Sprintf("%d", sr.Port))
		result += fmt.Sprintf("TLS %s:%d - %s<br>", sr.Target, sr.Port, msgTLS)
		if !okTLS {
			success = false
		}
	}

	if success {
		return true, "reachable"
	}
	return false, "unreachable"
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
		isReachable, status := checkXMPPConnectivity(domain)

		// Create a new server instance
		server := Server{
			Domain:      domain,
			Description: "Description here", // Populate as needed
			Features:    "Features here",    // Populate as needed
			Status:      status,
		}

		// Add the server to the database
		addServerToDB(server)

		// Store the result in the shared results slice
		mu.Lock()
		results = append(results, CrawlResult{
			Domain:      domain,
			IsReachable: isReachable,
			Message:     status,
		})
		mu.Unlock()

		// Show the results to the user
		fmt.Fprintf(w, "<h1>Crawl Results</h1><p>%s: %s - %t</p><p>%s</p>", domain, status, isReachable, getResultsHTML())
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

// Add a new server to the database
func addServer(w http.ResponseWriter, r *http.Request) {
	var s Server
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := `INSERT INTO servers (domain, description, features, status) VALUES (?, ?, ?, ?)`
	result, err := db.Exec(query, s.Domain, s.Description, s.Features, s.Status)
	if err != nil {
		http.Error(w, "Failed to add server", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Server added with ID %d", id)
}

// Update an existing server in the database
func updateServer(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	var s Server
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	query := `UPDATE servers SET domain = ?, description = ?, features = ?, status = ? WHERE id = ?`
	if _, err := db.Exec(query, s.Domain, s.Description, s.Features, s.Status, id); err != nil {
		http.Error(w, "Failed to update server", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Server updated successfully")
}

// Delete a server from the database
func deleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM servers WHERE id = ?`
	if _, err := db.Exec(query, id); err != nil {
		http.Error(w, "Failed to delete server", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Server deleted successfully")
}

// Add helper functions for templates
func add(a, b int) int {
	return a + b
}

func subtract(a, b int) int {
	return a - b
}

func someFunction() {
	// line 211: someStatement()
}

func anotherFunction() {
	// line 315: firstStatement()
	// line 317: secondStatement()
}

func finalFunction() {
	// line 376: finalStatement()
}

func init() {
	initDB()

	// Removed unused tmpl variable

	http.HandleFunc("/crawl", crawlHandler)
	http.HandleFunc("/servers", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listServers(w)
		case http.MethodPost:
			addServer(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/servers/update", updateServer)
	http.HandleFunc("/servers/delete", deleteServer)

	log.Println("Server started at http://localhost:8075")
	err := http.ListenAndServe(":8075", nil)
	if err != nil {
		log.Fatal("Server failed: ", err)
	}
}

// Handler to display the start page with an overview of endpoints
func startPageHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
		<h1>XMPP Connectivity Server</h1>
		<p>Welcome to the XMPP Connectivity Server. Below are the available endpoints:</p>
		<ul>
			<li><a href="/crawl">/crawl</a> - Check XMPP connectivity for a domain</li>
			<li><a href="/servers">/servers</a> - List all servers</li>
			<li><a href="/servers/new">/servers/new</a> - Add a new server</li>
			<li><a href="/metrics">/metrics</a> - Prometheus metrics</li>
		</ul>
	`)
}

func main() {
	initDB()
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	server := &http.Server{Addr: ":8075"}

	// Add Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", startPageHandler) // Ensure this route is registered
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
	http.HandleFunc("/servers/add", addServerHandler)

	// Add routes for the add server form
	http.HandleFunc("/servers/new", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
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
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Channel to listen for interrupt or terminate signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("Server started at http://localhost:8075")
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

// Handler to process the add server form
func addServerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var s Server
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
				http.Error(w, "Invalid JSON input", http.StatusBadRequest)
				log.Printf("Failed to decode request body: %v", err)
				return
			}
		} else {
			// Assume form data
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Failed to parse form data", http.StatusBadRequest)
				log.Printf("Failed to parse form data: %v", err)
				return
			}
			s.Domain = r.FormValue("domain")
			s.Description = r.FormValue("description")
			s.Features = r.FormValue("features")
			s.Status = r.FormValue("status")
		}

		// Perform input validation
		if err := validateServer(s); err != nil {
			http.Error(w, fmt.Sprintf("Validation error: %v", err), http.StatusBadRequest)
			log.Printf("Validation error for domain %s: %v", s.Domain, err)
			return
		}

		// Check XMPP connectivity
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

type Client struct {
	// Add fields as necessary
}

func (c *Client) MethodName() {
	// ...method body...
}

func (c *Client) AnotherFunction() {
	// ...method body...
}

func (c *Client) YetAnotherMethod() {
	// ...method body...
}

// Add the server to the database
func addServerToDB(s Server) {
	query := `INSERT INTO servers (domain, description, features, status) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, s.Domain, s.Description, s.Features, s.Status)
	if err != nil {
		log.Printf("Failed to add server: %v", err)
	}
}

// Validate server input
func validateServer(s Server) error {
	if s.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if s.Status == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}