import requests
from urllib.parse import urlparse
import socket
import re
import ssl

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
    # Replace with your PhishTank API key
    api_key = "YOUR_PHISHTANK_API_KEY"
    api_url = f"https://checkurl.phishtank.com/checkurl/"
    headers = {"format": "json", "app_key": api_key}
    try:
        response = requests.post(api_url, data={"url": url}, headers=headers)
        data = response.json()
        return data.get("results", {}).get("in_database") and data["results"]["valid"]
    except Exception:
        return False

def check_url(url):
    result = {
        "url": url,
        "ip_in_url": False,
        "blacklist": False,
        "https": False,
        "suspicious_url": False,
    }

    # Check if URL has an IP address instead of a domain name
    domain = urlparse(url).netloc
    result["ip_in_url"] = is_ip_address(domain)

    # Check HTTPS presence
    result["https"] = check_https(url)

    # Check in PhishTank or other blacklists
    result["blacklist"] = check_in_phishtank(url)

    # Pattern-based suspicious URL detection (e.g., using 'login' or 'verify' in URL path)
    suspicious_patterns = ["login", "signin", "verify", "account", "update", "secure", "bank", "ebay", "paypal"]
    if any(pattern in url.lower() for pattern in suspicious_patterns):
        result["suspicious_url"] = True

    # Analysis
    if result["ip_in_url"]:
        print(f"[WARNING] URL contains IP address instead of domain: {url}")
    if not result["https"]:
        print(f"[WARNING] URL does not use HTTPS: {url}")
    if result["blacklist"]:
        print(f"[ALERT] URL found in PhishTank database: {url}")
    if result["suspicious_url"]:
        print(f"[WARNING] URL contains suspicious patterns: {url}")

    return result

# Example usage
url_to_check = input("Enter the URL to check: ")
result = check_url(url_to_check)
print("\nPhishing Check Summary:")
print(result)
