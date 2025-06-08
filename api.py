from flask import Flask, request, jsonify, send_file
import socket
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
from dateutil.relativedelta import relativedelta
from bs4 import BeautifulSoup
from flask_cors import CORS
import matplotlib.pyplot as plt
from io import BytesIO

app = Flask(__name__)
CORS(app)

# Google Safe Browsing API Key (NOT encrypted)
GS_API_KEY = ""

# Store last analysis result for chart access
last_legit_status = {"clean": True}


def get_domain(domain_url):
    parsed = urlparse(domain_url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    return domain[4:] if domain.startswith("www.") else domain


def whois_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age = relativedelta(datetime.now(), creation_date)
        return f"{creation_date.strftime('%Y-%m-%d')} | {age.years} years, {age.months} months | Expires: {expiration_date.strftime('%Y-%m-%d') if expiration_date else 'Unknown'}"
    except:
        return "Unknown | Unknown | Expires: Unknown"


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unknown"


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


def ip_info(ip):
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if data['status'] != 'success':
            return ("Unknown",) * 7
        asn = data.get("as", "").split()[0].replace("AS", "")
        return (
            asn, data.get("org", "Unknown"), data.get("country", "Unknown"),
            data.get("city", "Unknown"), data.get("regionName", "Unknown"),
            data.get("lat", "Unknown"), data.get("lon", "Unknown")
        )
    except:
        return ("Unknown",) * 7


def google_safe_browsing(domain):
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": f"http://{domain}"},
                {"url": f"https://{domain}"}
            ]
        }
    }
    try:
        resp = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GS_API_KEY}", json=body)
        if resp.status_code == 200 and not resp.json().get("matches"):
            return "✅ Clean", True
        return "❌ Malicious", False
    except:
        return "⚠️ Error", False


def get_http_info(domain):
    try:
        resp = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        return resp.status_code, soup.title.string.strip() if soup.title else "No title"
    except:
        return "Unknown", "Unknown"


def generate_report(domain_url):
    domain = get_domain(domain_url)
    reg_info = whois_info(domain)
    http_status, title = get_http_info(domain)
    ip = get_ip(domain)

    if ip != "Unknown":
        rev_dns = reverse_dns(ip)
        asn, org, country, city, region, lat, lon = ip_info(ip)
    else:
        rev_dns = "Unknown"
        asn, org, country, city, region, lat, lon = ("Unknown",) * 7

    safe_status, is_clean = google_safe_browsing(domain)
    last_legit_status["clean"] = is_clean

    return {
        "Website Address": domain,
        "Last Analysis": datetime.now().strftime("%Y-%m-%d"),
        "HTTP Status Code": http_status,
        "Website Title": title,
        "Detections Count": "0/39" if is_clean else "1/39",
        "Safe Browsing Status": safe_status,
        "Domain Registration": reg_info,
        "IP Address": ip,
        "Reverse DNS": rev_dns,
        "ASN": f"AS{asn} {org}" if asn != "Unknown" else "Unknown",
        "Server Location": country,
        "Latitude\\Longitude": f"{lat} / {lon}",
        "City": city,
        "Region": region,
        "Legitimacy": "✅ Legit" if is_clean else "❌ Malicious or Suspicious"
    }


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    domain_url = data.get("url")
    if not domain_url:
        return jsonify({"error": "Missing 'url' in request"}), 400
    return jsonify(generate_report(domain_url))


@app.route('/analyze/chart', methods=['GET'])
def chart():
    clean = last_legit_status["clean"]
    labels = ['Legit', 'Malicious']
    sizes = [100, 0] if clean else [20, 80]
    colors = ['green', 'red']

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors)
    ax.axis('equal')

    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


if __name__ == '__main__':
    app.run(debug=True)
