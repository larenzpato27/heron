# quick phishing checker for the mail export - L. Garcia, march 2025
# TODO: make this nicer at some point
import re
import os
import sys

scores = {}
verdicts = []

KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

def check_mail(folder="./data/samples", flagged=[]):
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        raw = open(folder + "/" + fn, encoding="utf-8", errors="ignore").read()
        s = 0
        try:
            frm = re.search("From: (.*)", raw).group(1)
        except:
            frm = "?"
        try:
            subj = re.search("Subject: (.*)", raw).group(1)
        except:
            subj = "?"
        low = raw.lower()
        for kw in KEYWORDS:
            if kw in low:
                s = s + 1
        # links that look bad
        urls = re.findall("https?://[^\\s\"'<>]+", raw)
        for u in urls:
            if re.match("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", u):
                s = s + 3  # ip address url, very bad
            if "xn--" in u:
                s = s + 3
        # sender says paypal/microsoft/amazon but domain is weird
        if "paypal" in frm.lower() and "paypal.com" not in frm.lower():
            s = s + 3
        if "microsoft" in frm.lower() and "microsoft.com" not in frm.lower():
            s = s + 3
        if "amazon" in frm.lower() and "amazon.com" not in frm.lower():
            s = s + 3
        if "spf=fail" in low or "dmarc=fail" in low:
            s = s + 2
        # reply-to different from from
        try:
            rt = re.search("Reply-To: (.*)", raw).group(1)
            m1 = re.search("@([a-zA-Z0-9.-]+)", frm).group(1)
            m2 = re.search("@([a-zA-Z0-9.-]+)", rt).group(1)
            if m1 != m2:
                s = s + 2
        except:
            pass
        scores[fn] = s
        if s >= 5:
            verdicts.append((fn, "PHISHING", s))
            flagged.append(fn)
        elif s >= 3:
            verdicts.append((fn, "suspicious", s))
        else:
            verdicts.append((fn, "ok", s))
    print("checked", len(scores), "mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    out = open("results.txt", "w")
    out.write(str(verdicts))
    out.close()
    print("flagged:", flagged)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_mail(sys.argv[1])
    else:
        check_mail()
