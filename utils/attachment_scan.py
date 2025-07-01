import hashlib
import requests
from email import policy
from email.parser import BytesParser

API_KEY = "8445803baa0217d93437379d45d1c8a876ae488294adea2c61704a72b3fb2a75"  # Replace with your API key

VT_FILE_SEARCH_URL = "https://www.virustotal.com/api/v3/files/{}"

def extract_attachments(filepath):
    attachments = []
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            content = part.get_payload(decode=True)
            if filename and content:
                attachments.append((filename, content))
    return attachments

def get_file_hash(content):
    return hashlib.sha256(content).hexdigest()

def scan_attachment_vt(sha256_hash):
    headers = {
        "x-apikey": API_KEY
    }
    try:
        url = VT_FILE_SEARCH_URL.format(sha256_hash)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            if stats.get('malicious', 0) > 0:
                return f"⚠️ Malicious ({stats['malicious']} engines flagged)"
            elif stats.get('suspicious', 0) > 0:
                return f"⚠️ Suspicious ({stats['suspicious']} engines flagged)"
            else:
                return "✅ Clean"
        elif response.status_code == 404:
            return "Not found in VirusTotal"
        else:
            return "Error retrieving data"
    except Exception as e:
        return f"Error: {str(e)}"
