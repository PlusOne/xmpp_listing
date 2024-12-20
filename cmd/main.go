package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	_ "github.com/mattn/go-sqlite3"
	"github.com/xmppo/go-xmpp"
)

// Function to check if XMPP service is reachable
func checkXMPP(domain string) (bool, string) {
	// Create an XMPP client connection configuration
	client, err := xmpp.NewClient(fmt.Sprintf("%s:5222", domain), "", "", false)
	if err != nil {
		return false, "Error connecting to XMPP service"
	}

	// Attempt a simple connection
	err = client.ConnectC()
	if err != nil {
		return false, "XMPP service is down or unreachable"
	}

	// Close the connection
	client.Close()
	return true, "XMPP service is reachable"
}

// Struct to hold crawl results
type CrawlResult struct {
	Domain      string
	IsReachable bool
	Message     string
}

var results []CrawlResult
var mu sync.Mutex

// HTTP handler for the form
func crawlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get the domain from the form
		r.ParseForm()
		domain := r.FormValue("domain")

		// Check the XMPP service
		isReachable, message := checkXMPP(domain)

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
			<h1>Check XMPP Service</h1>
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
	if (err != nil) {
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
