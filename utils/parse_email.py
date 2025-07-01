import email
from email import policy

def extract_email_headers(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    return {
        'From': msg['From'],
        'To': msg['To'],
        'Subject': msg['Subject'],
        'Date': msg['Date'],
        'Received': msg.get_all('Received', []),
        'Authentication-Results': msg['Authentication-Results']  
    }
