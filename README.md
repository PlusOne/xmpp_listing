
# Introduction

XMPP Listing is a Go-based web application designed to manage and verify XMPP server connectivity. It allows users to add, update, and delete XMPP servers while performing connectivity checks such as SRV record lookup, TCP connection attempts, and TLS handshake verifications.

# Functions

- **verifySRVRecords(domain string)**: Retrieves SRV records for XMPP client and server from the specified domain.
- **attemptTCPConnection(host string, port string)**: Attempts a TCP connection to the given host and port with a timeout.
- **checkTLSHandshake(host string, port string)**: Performs a TLS handshake with the specified host and port.
- **checkXMPPConnectivity(domain string)**: Combines SRV lookup and connectivity checks to verify XMPP service availability.
- **crawlHandler(w http.ResponseWriter, r *http.Request)**: Handles HTTP requests for crawling and displaying XMPP connectivity results.
- **listServers(w http.ResponseWriter)**: Retrieves and returns the list of servers from the database in JSON format.
- **addServer(w http.ResponseWriter, r *http.Request)**: Adds a new server to the database after performing connectivity checks.
- **updateServer(w http.ResponseWriter, r *http.Request)**: Updates an existing server's details in the database.
- **deleteServer(w http.ResponseWriter, r *http.Request)**: Removes a server from the database based on its ID.
- **addServerForm(w http.ResponseWriter, r *http.Request)**: Displays the web form for adding a new server.
- **addServerHandler(w http.ResponseWriter, r *http.Request)**: Processes the submission of the add server form and inserts the server into the database.
- **initDB()**: Initializes the SQLite database and creates the required tables if they do not exist.
- **getResultsHTML() string**: Generates HTML to display the crawl results to the user.

# Todo

- Implement authentication for managing servers.
- Enhance the web interface with better styling and user experience.
- Add pagination to the server list view.
- Integrate more detailed logging and monitoring.
- Expand connectivity checks to include additional protocols or services.
- Write unit tests for all functionalities.
- Containerize the application using Docker for easier deployment.