package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
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
		return
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var s Server
		if err := rows.Scan(&s.ID, &s.Domain, &s.Description, &s.Features, &s.Status); err != nil {
			http.Error(w, "Failed to parse server data", http.StatusInternalServerError)
			return
		}
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(servers)
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

func main() {
	initDB()

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

	log.Println("Server started at http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Server failed: ", err)
	}
}
