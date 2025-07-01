import re
import requests
from email import policy
from email.parser import BytesParser

API_KEY = "8445803baa0217d93437379d45d1c8a876ae488294adea2c61704a72b3fb2a75"
VT_URL = "https://www.virustotal.com/api/v3/urls"

def extract_urls_from_email(filepath):
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    urls = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                text = part.get_content()
                urls += re.findall(r'https?://[^\s]+', text)
    else:
        text = msg.get_content()
        urls += re.findall(r'https?://[^\s]+', text)

    return list(set(urls))

def scan_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }
    try:
        response = requests.post(VT_URL, headers=headers, data={"url": url})
        if response.status_code == 200:
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{response.json()['data']['id']}"
            analysis = requests.get(analysis_url, headers=headers)
            if analysis.status_code == 200:
                stats = analysis.json()['data']['attributes']['stats']
                if stats.get('malicious', 0) > 0:
                    return f"⚠️ Malicious ({stats['malicious']} engines)"
                elif stats.get('suspicious', 0) > 0:
                    return f"⚠️ Suspicious ({stats['suspicious']} engines)"
                else:
                    return "✅ Clean"
        return "VirusTotal scan failed"
    except Exception as e:
        return f"Error: {str(e)}"
