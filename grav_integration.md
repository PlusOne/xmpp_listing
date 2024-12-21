# Grav CMS Integration for XMPP Connectivity Server

This guide provides instructions to integrate a Go-based XMPP connectivity server with Grav CMS. The server runs on port 8075 and exposes endpoints like `/server-info`, `/crawl`, and `/servers`. The integration fetches JSON data from these endpoints and displays it dynamically on Grav pages using Twig templates.

## Requirements

- Grav CMS
- Fetch Plugin for Grav (optional for advanced data fetching)

## Installation

1. **Install Grav CMS:**
   Follow the [official Grav installation guide](https://learn.getgrav.org/16/basics/installation) to set up Grav CMS.

2. **Install Fetch Plugin (Optional):**
   If you want to use the Fetch plugin for advanced data fetching, install it via the Grav Admin Panel or manually:
   ```bash
   bin/gpm install fetch
   ```

## Configuration

### Fetch JSON Data

Create a new page in Grav to fetch and display JSON data from the XMPP connectivity server.

1. **Create a New Page:**
   Create a new Markdown file in the `user/pages` directory, e.g., `01.server-info/default.md`.

   ```markdown
   ---
   title: Server Info
   fetch:
     url: 'http://localhost:8075/servers'
     cache: false
   process:
     twig: true
   ---

   # Server Information

   {% set servers = fetch %}
   {% if servers %}
     <ul>
     {% for server in servers %}
       <li>{{ server.domain }} - {{ server.status }}</li>
     {% endfor %}
     </ul>
   {% else %}
     <p>No server information available.</p>
   {% endif %}
   ```

2. **Fetch Plugin Configuration:**
   Ensure the Fetch plugin is enabled and configured correctly in `user/config/plugins/fetch.yaml`.

   ```yaml
   enabled: true
   cache: false
   ```

### Embed Go Server Frontend via iFrame

Create a new page in Grav to embed the Go server's frontend using an iFrame.

1. **Create a New Page:**
   Create a new Markdown file in the `user/pages` directory, e.g., `02.crawl/default.md`.

   ```markdown
   ---
   title: XMPP Crawl
   ---

   # XMPP Crawl

   <iframe src="http://localhost:8075/crawl" width="100%" height="600px"></iframe>
   ```

## Twig Examples

### Display JSON Data

Use Twig templates to fetch and display JSON data from the XMPP connectivity server.

1. **Create a New Page:**
   Create a new Markdown file in the `user/pages` directory, e.g., `03.servers/default.md`.

   ```markdown
   ---
   title: Servers List
   process:
     twig: true
   ---

   # Servers List

   {% set servers = url('http://localhost:8075/servers').json %}
   {% if servers %}
     <ul>
     {% for server in servers %}
       <li>{{ server.domain }} - {{ server.status }}</li>
     {% endfor %}
     </ul>
   {% else %}
     <p>No servers available.</p>
   {% endif %}
   ```

### Fetch and Display Data Using Fetch Plugin

1. **Create a New Page:**
   Create a new Markdown file in the `user/pages` directory, e.g., `04.server-info/default.md`.

   ```markdown
   ---
   title: Server Info
   fetch:
     url: 'http://localhost:8075/servers'
     cache: false
   process:
     twig: true
   ---

   # Server Information

   {% set servers = fetch %}
   {% if servers %}
     <ul>
     {% for server in servers %}
       <li>{{ server.domain }} - {{ server.status }}</li>
     {% endfor %}
     </ul>
   {% else %}
     <p>No server information available.</p>
   {% endif %}
   ```

## Instructions for Using the Integration

1. **Start the Go Server:**
   Ensure the Go-based XMPP connectivity server is running on port 8075.

   ```bash
   go run main.go
   ```

2. **Access Grav Pages:**
   Open your browser and navigate to the Grav CMS pages you created to view the integrated data.

   - [Server Info](http://localhost/01.server-info)
   - [XMPP Crawl](http://localhost/02.crawl)
   - [Servers List](http://localhost/03.servers)
   - [Server Info with Fetch Plugin](http://localhost/04.server-info)

By following these steps, you can seamlessly integrate the Go-based XMPP connectivity server with Grav CMS, fetching and displaying data dynamically on your Grav pages.
