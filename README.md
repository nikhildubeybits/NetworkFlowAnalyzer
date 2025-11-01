# Network Flow Analyzer

A web-based tool for real-time network traffic monitoring, analysis, and security assessment. It provides a user-friendly dashboard to capture network packets, detect anomalies, perform security scans, and stay updated with the latest cybersecurity news.

![Dashboard Screenshot](placeholder.png) <!-- TODO: Add a screenshot of your application's dashboard -->

## Features

*   **Packet Capture**: Capture live network traffic from a specified network interface.
*   **Anomaly Detection**: Analyze captured packets to identify unusual patterns, potential threats, and blocklisted IP addresses.
*   **Network Scanning**: Run Nmap scans against target hosts using predefined profiles to discover open ports and services.
*   **Threat Intelligence**:
    *   Look up IP addresses using Shodan to gather information about services and vulnerabilities.
    *   Dynamically block suspicious IP addresses.
*   **AI-Powered Analysis**: Get a plain-English explanation of network logs using an AI model.
*   **Cybersecurity News**: Fetches the latest cybersecurity news to keep you informed.
*   **Cloud Storage**: Upload log files directly to an AWS S3 bucket for archival and further analysis.
*   **Web Interface**: A clean and intuitive frontend built with Flask, HTML, and JavaScript.

## Tech Stack

*   **Backend**: Python, Flask
*   **Packet Analysis**: Scapy
*   **Network Scanning**: python-nmap
*   **Threat Intelligence**: Shodan
*   **Cloud Integration**: Boto3 (for AWS S3)
*   **AI Integration**: OpenRouter API
*   **Frontend**: HTML, CSS, JavaScript

## Project Structure

```
NetworkFlowAnalyzer/
├── app.py                  # Main Flask application, API endpoints
├── modules/
│   ├── packet_capture.py     # Logic for capturing packets
│   ├── anomaly_detection.py  # Logic for detecting anomalies
│   ├── nmap_scan.py          # Wrapper for Nmap scanning
│   ├── news_fetcher.py       # Fetches cybersecurity news
│   └── shodan_lookup.py      # Logic for Shodan IP lookups
├── templates/
│   ├── index.html            # Main dashboard page
│   └── schedule.html         # Page for scheduling captures
├── static/
│   ├── css/
│   └── js/
├── .env                    # Environment variables (API keys, etc.)
└── requirements.txt        # Python dependencies
```

## Setup and Installation

### 1. Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   Npcap (for packet capture on Windows) or `libpcap` (on Linux)
*   Nmap installed and available in your system's PATH.

### 2. Clone the Repository

```bash
git clone <your-repository-url>
cd NetworkFlowAnalyzer
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set Up Environment Variables

Create a file named `.env` in the root of the project directory and add the following variables. These are required for various features to work.

```ini
# News API (get from https://newsapi.org/)
NEWS_API_KEY="YOUR_NEWS_API_KEY"

# Shodan API (get from https://account.shodan.io/)
SHODAN_API_KEY="YOUR_SHODAN_API_KEY"

# OpenRouter API (get from https://openrouter.ai/keys)
OPENROUTER_API_KEY="YOUR_OPENROUTER_API_KEY"

# AWS Credentials for S3 Upload
AWS_ACCESS_KEY_ID="YOUR_AWS_ACCESS_KEY"
AWS_SECRET_ACCESS_KEY="YOUR_AWS_SECRET_KEY"
S3_BUCKET_NAME="your-s3-bucket-name"
```

## Running the Application

To start the Flask development server, run:

```bash
python app.py
```

The application will be available at `http://127.0.0.1:5000`.

## API Endpoints

The application exposes several API endpoints for its core functionalities.

---

#### `GET /api/capture`

Captures a specified number of network packets.
*   **Query Parameters**: `interface` (e.g., "Wi-Fi"), `packet_count` (e.g., 100).
*   **Returns**: A JSON array of captured packet data.

---

#### `GET /api/anomalies`

Captures fresh packets and analyzes them for anomalies.
*   **Returns**: A JSON object containing a list of detected anomalies.

---

#### `POST /api/blocklist/add`

Adds an IP address to the blocklist.
*   **Request Body**: `{ "ip": "x.x.x.x" }`
*   **Returns**: A confirmation message and the updated blocklist.

---

#### `GET /api/shodan/<ip_address>`

Performs a Shodan lookup for the given IP address.
*   **URL Parameter**: `ip_address` (e.g., "8.8.8.8").
*   **Returns**: A JSON object with Shodan data.

---

#### `GET /api/scan`

Runs an Nmap scan against a target.
*   **Query Parameters**:
    *   `target`: The IP address or hostname to scan (defaults to `127.0.0.1`).
    *   `profile`: The scan profile name (e.g., "Default Scan", "Intense Scan").
*   **Returns**: A JSON object with the Nmap scan results.

---

#### `GET /api/news`

Fetches recent cybersecurity news articles.
*   **Returns**: A JSON object containing news data.

---

#### `POST /api/ai-help`

Sends log data to an AI for analysis and explanation.
*   **Request Body**: `{ "logs": "log data as a string" }`
*   **Returns**: A JSON object with a plain-text explanation from the AI.

---

#### `POST /api/upload-to-s3`

Uploads a file to the configured AWS S3 bucket.
*   **Request Body**: `multipart/form-data` with a file part named `logFile`.
*   **Returns**: A success or error message.

## Future Improvements

*   **Scheduled Scans**: Implement the scheduling functionality for automated packet captures and scans.
*   **User Authentication**: Add user accounts and authentication to protect access.
*   **Real-time Firewall Rules**: Integrate with a firewall (like Windows Firewall or `iptables`) to automatically block IPs from the blocklist.
*   **Enhanced Visualization**: Create more interactive charts and graphs for visualizing network traffic.

---

*This README was generated with assistance from Gemini Code Assist.*