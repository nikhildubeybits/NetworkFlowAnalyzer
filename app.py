from flask import Flask, jsonify, render_template, request
from modules.packet_capture import start_capture as capture_packets
from modules.anomaly_detection import detect_anomalies
from modules.nmap_scan import scan_network
from modules.news_fetcher import get_cyber_news
from dotenv import load_dotenv
import os

load_dotenv() # Load environment variables from .env file

app = Flask(__name__)

# --- API Routes ---

@app.route('/api/capture', methods=['GET'])
def api_start_capture():
    """API endpoint to capture network packets."""
    # You can adjust the interface and count as needed
    # Ensure the interface 'Wi-Fi' or 'Ethernet' matches your system
    # A higher packet count is better for anomaly detection.
    try:
        packets = capture_packets(interface="Wi-Fi", packet_count=100)
        return jsonify(packets)
    except Exception as e:
        # Return a proper error response if capturing fails
        return jsonify({"error": str(e)}), 500

@app.route('/api/anomalies', methods=['GET'])
def api_detect_anomalies():
    """API endpoint to capture packets and detect anomalies."""
    try:
        # Capture a fresh batch of packets specifically for analysis
        packets = capture_packets(interface="Wi-Fi", packet_count=200)
        anomalies = detect_anomalies(packets)
        return jsonify(anomalies)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['GET'])
def api_run_scan():
    """API endpoint to run a network scan."""
    # For now, target is hardcoded to localhost, but we get profile from the request
    target = request.args.get('target', '127.0.0.1')
    profile_name = request.args.get('profile', 'Default Scan')
    
    # Convert frontend profile name ('Default Scan') to backend key ('default')
    profile_key = profile_name.split(' ')[0].lower()

    try:
        results = scan_network(target=target, profile=profile_key)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/news', methods=['GET'])
def api_get_news():
    """API endpoint to fetch cybersecurity news."""
    api_key = os.getenv("NEWS_API_KEY")
    news_data = get_cyber_news(api_key)
    return jsonify(news_data)

# --- Frontend Route ---

@app.route('/')
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)