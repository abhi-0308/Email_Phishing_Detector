import dns.resolver

def get_domain_from_email(email_addr):
    try:
        return email_addr.split('@')[1]
    except:
        return None

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(f"{domain}", "TXT")
        for rdata in answers:
            if 'v=spf1' in str(rdata):
                return "SPF record found"
        return "No SPF record"
    except:
        return "SPF check failed"

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            if 'v=DMARC1' in str(rdata):
                return "DMARC record found"
        return "No DMARC record"
    except:
        return "DMARC check failed"

def check_dkim(domain):
    # Simplified check
    return "DKIM-Signature present"  # Placeholder for real DKIM check
