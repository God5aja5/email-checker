#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
import re, socket, ssl, datetime, requests, time

app = Flask(__name__)

# ---- HELPERS ----
def check_format(email):
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$"
    return re.match(pattern, email) is not None

def get_domain(email):
    """Extract domain part"""
    return email.split("@")[-1]

def check_mx(domain):
    """Check MX records using socket fallback"""
    try:
        addr_info = socket.getaddrinfo(domain, None)
        return list(set([x[4][0] for x in addr_info]))
    except Exception as e:
        return [f"Error: {str(e)}"]

def check_ssl(domain):
    """Fetch SSL certificate info"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "subject": dict(x[0] for x in cert["subject"]),
                    "valid_from": cert["notBefore"],
                    "valid_to": cert["notAfter"],
                }
    except Exception as e:
        return {"ssl_error": str(e)}

def reverse_dns(domain):
    """Get IP + reverse DNS"""
    try:
        ip = socket.gethostbyname(domain)
        rev = socket.gethostbyaddr(ip)
        return {"ip": ip, "hostname": rev[0]}
    except Exception as e:
        return {"reverse_dns_error": str(e)}

def check_free_provider(domain):
    free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"]
    return domain in free_domains

def check_disposable(domain):
    disposable = ["tempmail", "10minutemail", "guerrillamail", "yopmail", "mailinator"]
    return any(d in domain for d in disposable)

def email_metadata(email, domain):
    return {
        "length": len(email),
        "local_part_length": len(email.split("@")[0]),
        "domain_length": len(domain),
        "tld": domain.split(".")[-1],
        "is_free_provider": check_free_provider(domain),
        "is_disposable": check_disposable(domain),
    }

# ---- NAMESCAN BREACH CHECK ----
def check_breaches(email):
    headers = {
        'authority': 'webapi.namescan.io',
        'accept': 'application/json',
        'content-type': 'application/json',
        'origin': 'https://namescan.io',
        'referer': 'https://namescan.io/',
        'user-agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
    }

    json_data = {
        'email': email,
        'g-recaptcha-response': None,
    }

    try:
        r = requests.post(
            'https://webapi.namescan.io/v1/freechecks/email/breaches',
            headers=headers, json=json_data, timeout=15
        )
        # Retry once if rate limited or server error
        if r.status_code in [429, 502, 503]:
            time.sleep(3)
            r = requests.post(
                'https://webapi.namescan.io/v1/freechecks/email/breaches',
                headers=headers, json=json_data, timeout=15
            )

        if r.status_code == 200:
            data = r.json()
            breaches = []
            for breach in data.get("breaches", []):
                breaches.append({
                    "title": breach.get("title", "Unknown"),
                    "domain": breach.get("domain", "N/A"),
                    "breachDate": breach.get("breachDate", "N/A"),
                    "dataExposed": breach.get("dataClasses", "N/A"),
                    "info": breach.get("description", "")
                })
            return {"breached": bool(breaches), "breaches": breaches}
        else:
            return {"breached": "unknown", "error": f"Error {r.status_code}"}
    except Exception as e:
        return {"breached": "unknown", "error": str(e)}

# ---- API ----
@app.route("/osint", methods=["GET"])
def osint_email():
    email = request.args.get("email", "").strip()
    if not email:
        return jsonify({"error": "Email parameter is required"}), 400

    domain = get_domain(email)

    result = {
        "email": email,
        "valid_format": check_format(email),
        "domain": domain,
        "metadata": email_metadata(email, domain),
        "breach_check": check_breaches(email),
        "mx_records": check_mx(domain),
        "ssl_info": check_ssl(domain),
        "reverse_dns": reverse_dns(domain),
        "checked_at": datetime.datetime.utcnow().isoformat() + "Z"
    }

    return jsonify(result)

# ---- MAIN ----
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
