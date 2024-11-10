import socket
import os
import subprocess
import requests
from urllib.parse import urlparse
import ssl
from flask import Flask, render_template, request,redirect,url_for,session, flash , send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import bcrypt
from flask_mysqldb import MySQL
import tempfile

app = Flask(__name__)
weblocksql = MySQL(app)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'weblock'
app.secret_key = 'your_secret_key_here'

class RegistrationForm(FlaskForm):
    name = StringField('name', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField("register")

class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField("login")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = weblocksql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        weblocksql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = weblocksql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        else:
            flash("Login Failed. Try again with a valid password")

        cursor.close()

    return render_template('login.html', form=form)

def is_ip_address(url):
    try:
        socket.inet_aton(url)
        return True
    except socket.error:
        return False

def check_https(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or parsed_url.path

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version() is not None
    except Exception:
        return False

def check_in_phishtank(url):
    api_key = "YOUR_PHISHTANK_API_KEY"
    api_url = f"https://checkurl.phishtank.com/checkurl/"
    headers = {"format": "json", "app_key": api_key}
    try:
        response = requests.post(api_url, data={"url": url}, headers=headers)
        data = response.json()
        return data.get("results", {}).get("in_database") and data["results"]["valid"]
    except Exception:
        return False

def check_phishing(url):
    result = {
        "ip_in_url": is_ip_address(url),
        "https": check_https(url),
        "blacklist": check_in_phishtank(url),
        "suspicious_url": any(pattern in url.lower() for pattern in ["login", "signin", "verify", "account", "update", "secure", "bank", "ebay", "paypal","htttp" , "cloudflare" ,"ngrok" , "onion", "LocalXpose"]),
    }

    analysis_lines = []
    if result["ip_in_url"]:
        analysis_lines.append(f"[WARNING] URL contains IP address instead of domain: {url}")
    if not result["https"]:
        analysis_lines.append(f"[WARNING] URL does not use HTTPS: {url}")
    if result["blacklist"]:
        analysis_lines.append(f"[ALERT] URL found in PhishTank database: {url}")
    if result["suspicious_url"]:
        analysis_lines.append(f"[WARNING] URL contains suspicious patterns: {url}")

    if not analysis_lines:
        analysis_lines.append("No significant phishing indicators detected.")
    
    return "\n".join(analysis_lines)

def run_nmap_scan(target, scan_type):
    if scan_type == '1':
        command = f"nmap -T4 -A -v {target}" 
    elif scan_type == '2':
        command = f"nmap -sS -sU -T4 -A -v {target}"  
    else:
        return "Invalid scan type selected."

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error executing scan: {e}"


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analysis', methods=['GET'])
def analysis():
    return render_template('analysis.html')

@app.route('/scan', methods=['POST'])
def scan():
    website_name = request.form.get('url')
    website_url = request.form.get('url2')

    try:
        ip_address = socket.gethostbyname(website_url)
    except socket.gaierror:
        ip_address = "Could not resolve the website name."

    phishing_results = {
        "ip_in_url": is_ip_address(website_url),
        "https": check_https(website_url),
        "blacklist": check_in_phishtank(website_url),
        "suspicious_url": any(pattern in website_url.lower() for pattern in ["login", "signin", "verify", "account", "update", "secure", "bank", "ebay", "paypal"]),
    }

    analysis_result = check_phishing(website_url)
    safety_score = calculate_safety_score(phishing_results)

    return render_template('analysis.html', website_name=website_name, analysis_result=analysis_result, ip_address=ip_address, safety_score=safety_score)

@app.route('/download_scan_result')
def download_scan_result():
    file_path = request.args.get('file_path')  # Get the file path from the query parameters
    return send_file(file_path, as_attachment=True, download_name='scan_result.txt')


@app.route('/detailed_scan', methods=['POST'])
def detailed_scan():
    website_name = request.form.get('url')
    website_url = request.form.get('url2')
    scan_type = request.form.get('scan_type')

    try:
        ip_address = socket.gethostbyname(website_url)
    except socket.gaierror:
        ip_address = "Could not resolve the website name."

    analysis_result = check_phishing(website_url)
    nmap_result = run_nmap_scan(ip_address, scan_type)

    # Save the results to a temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.txt')
    with open(temp_file.name, 'w') as f:
        f.write(f"Website Name: {website_name}\n")
        f.write(f"Website URL: {website_url}\n")
        f.write(f"IP Address: {ip_address}\n")
        f.write("Phishing Analysis:\n")
        f.write(analysis_result + "\n\n")
        f.write("Nmap Scan Result:\n")
        f.write(nmap_result)

    # Pass the temp file path to the template
    return render_template('details.html', website_name=website_name, website_url=website_url,
                           ip_address=ip_address, additional_info=analysis_result, nmap_result=nmap_result,
                           file_path=temp_file.name)

def calculate_safety_score(phishing_results):
    score = 100  # Start with a perfect score
    if phishing_results["ip_in_url"]:
        score -= 20
    if not phishing_results["https"]:
        score -= 20
    if phishing_results["blacklist"]:
        score -= 40
    if phishing_results["suspicious_url"]:
        score -= 20
    return max(score, 0)  # Ensure score is non-negative

if __name__ == "__main__":
    app.run(debug=True)