from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import boto3
from modules.packet_capture import start_capture as capture_packets
# Import all necessary functions from anomaly_detection module
from modules.anomaly_detection import detect_anomalies, blocklisted_ips, add_to_blocklist, update_threat_feed
from modules.nmap_scan import scan_network
from modules.news_fetcher import get_cyber_news
from modules.shodan_lookup import get_shodan_info
from dotenv import load_dotenv
import os
import uuid
import smtplib
import datetime
from email.mime.text import MIMEText

load_dotenv() # Load environment variables from .env file
from datetime import timedelta

app = Flask(__name__)

# --- Authentication Setup ---
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "a_super_secret_key_for_development")
login_manager = LoginManager()
login_manager.init_app(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
login_manager.login_view = 'login' # Redirect to /login if user is not authenticated

class User(UserMixin):
    def __init__(self, id, username, password, email, approval_date=None):
        self.id = id
        self.username = username
        self.email = email
        self.approval_date = approval_date if approval_date else datetime.date.today()
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# In-memory "database" for demonstration.
# In a real app, use a proper database like SQLite, PostgreSQL, etc.
users = {
    "1": User(id="1", username="admin", password="password123", email="admin@example.com", approval_date=datetime.date.today()),
    "2": User(id="2", username="netadmin", password="password456", email="netadmin@example.com", approval_date=datetime.date.today())
}

# In-memory storage for pending user registrations
pending_users = {}

# In-memory storage for password reset tokens
password_reset_tokens = {}

def get_next_user_id():
    return str(max([int(k) for k in users.keys()] + [0]) + 1)

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# --- Protected API Routes ---

@app.route('/api/capture', methods=['GET'])
@login_required
def api_start_capture():
    """API endpoint to capture network packets."""
    # A higher packet count is better for anomaly detection.
    try:
        packets = capture_packets(interface="Wi-Fi", packet_count=100)
        return jsonify(packets)
    except Exception as e:
        # Return a proper error response if capturing fails
        return jsonify({"error": str(e)}), 500

@app.route('/api/anomalies', methods=['GET'])
@login_required
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
@login_required
def api_add_to_blocklist():
    """API endpoint to add an IP to the blocklist."""
    data = request.get_json()
    ip_to_block = data.get('ip')
    if not ip_to_block:
        return jsonify({"error": "IP address is required"}), 400
    
    add_to_blocklist(ip_to_block)
    return jsonify({"message": f"IP {ip_to_block} added to blocklist.", "blocklist": list(blocklisted_ips)})

@app.route('/api/shodan/<ip_address>', methods=['GET'])
@login_required
def api_shodan_lookup(ip_address):
    """API endpoint for Shodan IP lookup."""
    shodan_data = get_shodan_info(ip_address)
    return jsonify(shodan_data)

@app.route('/api/threat-intel/update', methods=['POST'])
@login_required
def api_update_threat_intel():
    """API endpoint to trigger an update of the threat intelligence feed."""
    try:
        count = update_threat_feed()
        # The update_threat_feed function now reloads the list in memory automatically.
        return jsonify({"message": f"Threat intelligence feed updated successfully. Loaded {count} malicious IPs."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['GET'])
@login_required
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
@login_required
def api_get_news():
    """API endpoint to fetch cybersecurity news."""
    api_key = os.getenv("NEWS_API_KEY")
    news_data = get_cyber_news(api_key)
    return jsonify(news_data)

@app.route('/api/ai-help', methods=['POST'])
@login_required
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
@login_required
def upload_to_s3():
    """API endpoint to upload a file to AWS S3."""
    import hashlib # Import the hashing library
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

    # Get the client-side hash from the form data
    client_hash = request.form.get('fileHash')
    if not client_hash:
        return jsonify({"error": "File hash is missing from the request."}), 400

    if file:
        # --- Hashing Verification Step ---
        # Read file content and calculate its hash
        file_content = file.read()
        server_hash = hashlib.sha256(file_content).hexdigest()

        if server_hash != client_hash:
            return jsonify({"error": "File integrity check failed. Hashes do not match."}), 400
        
        file.seek(0) # Reset file pointer to the beginning before uploading
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

# --- Protected Frontend Routes ---

@app.route('/')
@login_required
def index():
    """Serves the main dashboard page."""
    return render_template('index.html')

@app.route('/schedule')
@login_required
def schedule_page():
    """Serves the schedule capture page."""
    return render_template('schedule.html')

# --- Add Login and Logout Logic ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        session.permanent = True # Ensure the session is permanent upon login
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Find user by username
        user_to_login = None
        for user in users.values():
            if user.username == username:
                user_to_login = user
                break
        
        if user_to_login and user_to_login.check_password(password):
            # --- NEW: Check if the user's access has expired (1 month) ---
            if user_to_login.approval_date:
                expiration_period = datetime.timedelta(days=30)
                if datetime.date.today() > user_to_login.approval_date + expiration_period:
                    flash('Your account access has expired. Please contact the administrator.', 'danger')
                    return redirect(url_for('login'))

            session.permanent = True # Make the session permanent
            login_user(user_to_login)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user_to_reset = None
        for user in users.values():
            if user.email == email:
                user_to_reset = user
                break
        
        if user_to_reset:
            token = str(uuid.uuid4())
            password_reset_tokens[token] = {
                'user_id': user_to_reset.id,
                'expires_at': datetime.datetime.utcnow() + datetime.timedelta(hours=1) # Token expires in 1 hour
            }
            try:
                send_password_reset_email(email, token)
                flash('A password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash(f'Could not send reset email. Please try again later. Error: {e}', 'danger')
        else:
            # Still show a success message to prevent user enumeration
            flash('If an account with that email exists, a reset link has been sent.', 'info')
        
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    token_data = password_reset_tokens.get(token)

    if not token_data or token_data['expires_at'] < datetime.datetime.utcnow():
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        user_id = token_data['user_id']
        user = users.get(user_id)
        if user:
            # In a real app, you would update the database here
            user.password_hash = generate_password_hash(password)
            # Invalidate the token after use
            del password_reset_tokens[token]
            flash('Your password has been successfully reset! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('An unexpected error occurred. Please try again.', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # --- Validation ---
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if any(u.username == username for u in users.values()):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        # --- Store Pending User ---
        token = str(uuid.uuid4())
        pending_users[token] = {
            'first_name': first_name,
            'last_name': last_name,
            'username': username,
            'email': email,
            'password': password
        }

        # --- Send Approval Email ---
        try:
            send_approval_email(token, username, email)
            flash('Registration successful! Your account is pending approval.', 'success')
        except Exception as e:
            # If email fails, remove pending user to allow them to try again
            del pending_users[token]
            flash(f'Could not send approval email. Please try again later. Error: {e}', 'danger')

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/approve/<token>')
def approve(token):
    if token not in pending_users:
        return "<h1>Invalid or expired approval token.</h1>", 404

    user_data = pending_users.pop(token)
    new_id = get_next_user_id()
    new_user = User(id=new_id, username=user_data['username'], password=user_data['password'], email=user_data['email'], approval_date=datetime.date.today())
    users[new_id] = new_user

    return "<h1>User Approved!</h1><p>The user '{}' has been approved and can now log in.</p>".format(user_data['username'])

@app.route('/deny/<token>')
def deny(token):
    if token not in pending_users:
        return "<h1>Invalid or expired approval token.</h1>", 404
    
    user_data = pending_users.pop(token)
    # Optionally, send an email to the user informing them of the denial
    return "<h1>User Denied.</h1><p>The registration for '{}' has been denied.</p>".format(user_data['username'])

def send_approval_email(token, username, user_email):
    """Sends an email to the approver with approve/deny links."""
    approver_email = os.getenv("APPROVER_EMAIL")
    if not approver_email:
        raise Exception("APPROVER_EMAIL is not set in the environment.")

    approve_url = url_for('approve', token=token, _external=True)
    deny_url = url_for('deny', token=token, _external=True)

    body = f"""
    A new user has registered for the Network SecureFlow Analyzer.

    Username: {username}
    Email: {user_email}

    Please review and take action:

    Approve: {approve_url}
    Deny: {deny_url}
    """

    msg = MIMEText(body)
    msg['Subject'] = 'New User Registration Approval Required'
    msg['From'] = os.getenv('MAIL_USERNAME')
    msg['To'] = approver_email

    with smtplib.SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT', 587))) as server:
        server.starttls()
        server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
        server.send_message(msg)

def send_password_reset_email(user_email, token):
    """Sends a password reset link to the user."""
    reset_url = url_for('reset_password', token=token, _external=True)

    body = f"""
    You are receiving this email because a password reset request was made for your account on the Network SecureFlow Analyzer.

    Please click the link below to reset your password. This link is valid for one hour.

    {reset_url}

    If you did not request a password reset, please ignore this email.
    """

    msg = MIMEText(body)
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = os.getenv('MAIL_USERNAME')
    msg['To'] = user_email

    with smtplib.SMTP(os.getenv('MAIL_SERVER'), int(os.getenv('MAIL_PORT', 587))) as server:
        server.starttls()
        server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
        server.send_message(msg)


if __name__ == '__main__':
    app.run(debug=True)