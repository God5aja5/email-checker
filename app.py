#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
import requests, re, socket, ssl
import datetime

app = Flask(__name__)

# ---- CONFIG ----
REQUEST_TIMEOUT = 15

# Cookies + headers (from your example)
COOKIES = {
    '2ip_js_challenge_salt': 'M1PKL2j+Um',
    '2ip_js_challenge': 't87bcnAD9p5xOb7MqxOag2tYics',
    '_ga': 'GA1.1.953592212.1757060054',
    'PHPSESSID': '09u7j8dljh2pu75vgstgbbgli0',
    '_ga_EEJ7TBY7HX': 'GS2.1.s1757060054$o1$g1$t1757061448$j55$l0$h2038854394',
}

HEADERS = {
    'authority': '2ip.io',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'no-cache',
    'pragma': 'no-cache',
    'referer': 'https://2ip.io/pwned/',
    'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'sec-ch-ua-platform-version': '"14.0.0"',
    'user-agent': 'Mozilla/5.0 (Linux; Android 14; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36',
}

# ---- HELPERS ----
def check_breaches(email):
    """Check if email is in breach database via 2ip.io"""
    try:
        url = f"https://2ip.io/?area=ajaxHaveIBeenPwned&query={email}"
        res = requests.get(url, cookies=COOKIES, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        if res.status_code == 200 and res.text.strip():
            return {"breach_info": res.text.strip()}
        else:
            return {"breach_error": f"Error {res.status_code}"}
    except Exception as e:
        return {"breach_error": str(e)}

def check_format(email):
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$"
    return re.match(pattern, email) is not None

def get_domain(email):
    """Extract domain part"""
    return email.split("@")[-1]

def check_mx(domain):
    """Check MX records using socket (fallback if dnspython blocked)"""
    try:
        # try dnspython if installed
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange) for r in mx_records]
    except Exception:
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
