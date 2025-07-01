from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
import os

from utils.parse_email import extract_email_headers
from utils.check_spf_dkim import get_domain_from_email
from utils.virustotal_scan import extract_urls_from_email, scan_url_virustotal
from utils.attachment_scan import extract_attachments, get_file_hash, scan_attachment_vt

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'eml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    verdict = None
    reasons = []

    if request.method == 'POST':
        if 'email_file' not in request.files:
            return redirect(request.url)
        file = request.files['email_file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            result = extract_email_headers(filepath)
            sender = result.get('From', '')
            domain = get_domain_from_email(sender)

            # Authentication-Results Header Parsing
            auth_header = result.get('Authentication-Results') or ""
            spf = "Pass" if "spf=pass" in auth_header.lower() else "Fail"
            dkim = "Pass" if "dkim=pass" in auth_header.lower() else "Fail"
            dmarc = "Pass" if "dmarc=pass" in auth_header.lower() else "Fail"

            result['SPF'] = spf
            result['DKIM'] = dkim
            result['DMARC'] = dmarc

            if spf == "Fail":
                reasons.append("SPF failed according to Authentication-Results header.")
            if dmarc == "Fail":
                reasons.append("DMARC failed according to Authentication-Results header.")

            # URL Scan
            urls = extract_urls_from_email(filepath)
            url_results = {}
            suspicious_keywords = ["login", "verify", "secure", "account", "paypal", "reset", "bank", "signin"]
            safe_domains = ["google.com", "accounts.google.com", "myaccount.google.com"]

            for url in urls:
                scan_result = scan_url_virustotal(url)
                url_results[url] = scan_result

                if "malicious" in scan_result.lower() or "suspicious" in scan_result.lower():
                    reasons.append(f"URL flagged: {url} — {scan_result}")
                elif not any(domain in url for domain in safe_domains):
                    if any(keyword in url.lower() for keyword in suspicious_keywords):
                        reasons.append(f"Suspicious URL structure: {url}")

            result['URLs'] = url_results

            # Attachment Scan
            attachments = extract_attachments(filepath)
            attachment_results = {}

            for filename, content in attachments:
                file_hash = get_file_hash(content)
                scan_result = scan_attachment_vt(file_hash)
                attachment_results[filename] = scan_result

                if "malicious" in scan_result.lower() or "suspicious" in scan_result.lower():
                    reasons.append(f"Attachment flagged: {filename} — {scan_result}")

            result['Attachments'] = attachment_results

            # Verdict
            if reasons:
                verdict = {
                    "label": "Phishing Email",
                    "color": "red",
                    "reasons": reasons
                }
            else:
                verdict = {
                    "label": "Not a Phishing Email",
                    "color": "green",
                    "reasons": ["No suspicious indicators found."]
                }

    return render_template("index.html", result=result, verdict=verdict)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))

