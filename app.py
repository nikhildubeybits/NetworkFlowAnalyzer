from flask import Flask, render_template, jsonify, request
from dotenv import load_dotenv
import os
from collections import Counter
import modules.packet_capture as pc
import modules.anomaly_detection as ad
import modules.nmap_scan as nm
import modules.news_fetcher as nf

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Get News API key from environment
news_api_key = os.getenv("NEWS_API_KEY")
# We will check for the key in the route itself to allow the app to run without it.

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/start_capture')
def start_capture():
    packets = pc.start_capture(interface="Wi-Fi", packet_count=50)
    return jsonify({"packets": packets})

@app.route('/api/get_anomalies')
def get_anomalies():
    anomalies = ad.detect_anomalies()
    return jsonify(anomalies)

@app.route('/api/nmap_scan')
def nmap_scan():
    profile = request.args.get('profile', 'default')
    scan_results = nm.scan_network('127.0.0.1', profile=profile)
    return jsonify(scan_results)

@app.route('/api/anomaly_summary')
def anomaly_summary():
    anomalies = ad.detect_anomalies()
    severity_counts = Counter(a['severity'] for a in anomalies)
    ip_counts = Counter(a['source_ip'] for a in anomalies)
    return jsonify({
        'severity_counts': severity_counts,
        'ip_counts': ip_counts
    })

@app.route('/api/manage_ip', methods=['POST'])
def manage_ip():
    data = request.json
    ip = data.get("ip")
    action = data.get("action")

    if not ip or not action:
        return jsonify({"status": "error", "message": "Missing IP or action"}), 400

    if action == "block":
        pc.blocked_ips.add(ip)
        return jsonify({"status": "success", "message": f"IP {ip} added to blocklist."})
    elif action == "whitelist":
        ad.whitelisted_ips.add(ip)
        return jsonify({"status": "success", "message": f"IP {ip} added to whitelist."})
    
    return jsonify({"status": "error", "message": "Invalid action"}), 400

@app.route('/api/get_news')
def get_news():
    news_data = nf.get_cyber_news(news_api_key)
    return jsonify(news_data)



if __name__ == '__main__':
    app.run(debug=True)