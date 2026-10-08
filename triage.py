# quick phishing checker for the mail export - L. Garcia, march 2025
# TODO: make this nicer at some point
import re
import os
import sys
from email import message_from_string, policy
from email.utils import parseaddr



KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]
BRANDS = ["paypal", "microsoft", "amazon"]

URL_RE = re.compile("https?://[^\\s\"'<>]+")
IP_URL_RE = re.compile("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")

# Points added by each indicator, and the score thresholds of each verdict.
W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2
PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

def sender_domain(header_value):
    """Return the domain of the address in a From/Reply-To value, or None."""
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.split("@")[1]

def verdict_for(score):
    """Map a score to a verdict."""
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "ok"

def report(verdicts):
    """Print the verdicts and save them to results.txt."""
    print("checked", len(verdicts), "mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    with open("results.txt", "w", encoding="utf-8") as out:
        out.write(str(verdicts))
    print("flagged:", [v[0] for v in verdicts if v[1] == "PHISHING"])

def keyword_score(raw):
    s = 0
    low = raw.lower()
    for kw in KEYWORDS:
        if kw in low:
            s = s + W_KEYWORD
    return s

def link_score(raw):
    """Points for links to a bare IP address or to a punycode domain."""
    s = 0
    for url in URL_RE.findall(raw):
        if IP_URL_RE.match(url):
            s = s + W_IP_LINK
        if "xn--" in url:
            s = s + W_PUNYCODE_LINK
    return s

def brand_score(frm):
    s = 0
    for brand in BRANDS:
        if brand in frm.lower() and brand + ".com" not in frm.lower():
            s = s + W_BRAND_MISMATCH
    return s

def auth_score(raw):
    s = 0
    low = raw.lower()
    if "spf=fail" in low or "dmarc=fail" in low:
        s = s + W_AUTH_FAIL
    return s

def reply_to_score(frm, rt):
    s = 0
    from_domain = sender_domain(frm)
    reply_domain = sender_domain(rt)
    if from_domain and reply_domain and from_domain != reply_domain:
        s = s + W_REPLY_TO_MISMATCH
    return s

def score_email(raw):
    """Sum the points of every indicator for one raw message."""
    msg = message_from_string(raw, policy=policy.default)
    frm = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return (keyword_score(raw) + link_score(raw) + brand_score(frm)
            + auth_score(raw) + reply_to_score(frm, reply_to))

def check_mail(folder):
    verdicts = []
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        s = score_email(raw)
        verdicts.append((fn, verdict_for(s), s))
    return verdicts

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python triage.py <folder-with-eml-files>", file=sys.stderr)
        sys.exit(2)
    try:
        report(check_mail(sys.argv[1]))
    except FileNotFoundError:
        print("error: no such folder:", sys.argv[1], file=sys.stderr)
        sys.exit(2)
