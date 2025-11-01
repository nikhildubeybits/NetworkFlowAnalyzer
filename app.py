from flask import Flask, jsonify, render_template, request
import requests # Import the requests library
import boto3
from modules.packet_capture import start_capture as capture_packets
from modules.anomaly_detection import detect_anomalies, blocklisted_ips, add_to_blocklist
from modules.nmap_scan import scan_network
from modules.news_fetcher import get_cyber_news
from modules.shodan_lookup import get_shodan_info
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

@app.route('/api/blocklist/add', methods=['POST'])
def api_add_to_blocklist():
    """API endpoint to add an IP to the blocklist."""
    data = request.get_json()
    ip_to_block = data.get('ip')
    if not ip_to_block:
        return jsonify({"error": "IP address is required"}), 400
    
    add_to_blocklist(ip_to_block)
    return jsonify({"message": f"IP {ip_to_block} added to blocklist.", "blocklist": list(blocklisted_ips)})

@app.route('/api/shodan/<ip_address>', methods=['GET'])
def api_shodan_lookup(ip_address):
    """API endpoint for Shodan IP lookup."""
    shodan_data = get_shodan_info(ip_address)
    return jsonify(shodan_data)

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

@app.route('/api/ai-help', methods=['POST'])
def ai_help():
    """API endpoint to get AI analysis of logs from OpenRouter."""
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        return jsonify({"error": "OpenRouter API key is not configured on the server."}), 500

    log_data = request.json.get('logs')
    if not log_data:
        return jsonify({"error": "No log data provided."}), 400

    prompt = f"""You are a friendly and helpful cybersecurity expert.
A user has provided the following network packet capture logs in CSV format.
Please analyze these logs and provide a simple, clear, and concise explanation of what is happening on the network.
Focus on identifying the main types of traffic, any potential security concerns (like unusual protocols or connections), and what the overall activity suggests.
Format your response in simple paragraphs. Do not just repeat the log data.

Log Data:
---
{log_data}
---
"""

    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}"
            },
            json={
                "model": "mistralai/mistral-7b-instruct", # A good, fast model
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=30
        )
        response.raise_for_status()
        api_response = response.json()
        explanation = api_response['choices'][0]['message']['content']
        return jsonify({"explanation": explanation})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to communicate with the AI service: {e}"}), 502

@app.route('/api/upload-to-s3', methods=['POST'])
def upload_to_s3():
    """API endpoint to upload a file to AWS S3."""
    aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    bucket_name = os.getenv("S3_BUCKET_NAME")

    if not all([aws_access_key, aws_secret_key, bucket_name]):
        return jsonify({"error": "AWS credentials or S3 bucket name are not configured on the server."}), 500

    if 'logFile' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files['logFile']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400

    if file:
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key
            )
            # The filename is passed from the frontend
            s3_client.upload_fileobj(file, bucket_name, file.filename)
            return jsonify({"message": f"File '{file.filename}' uploaded successfully to S3 bucket '{bucket_name}'."})
        except Exception as e:
            return jsonify({"error": f"Failed to upload to S3: {str(e)}"}), 500

    return jsonify({"error": "An unknown error occurred."}), 500

# --- Frontend Route ---

@app.route('/')
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/schedule')
def schedule_page():
    """Serves the schedule capture page."""
    return render_template('schedule.html')

if __name__ == '__main__':
    app.run(debug=True)