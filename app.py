from flask import Flask, request, render_template, send_from_directory
import subprocess
import os
import time
import json
from werkzeug.utils import secure_filename

app = Flask(__name__)

RESULTS_DIR = "results"


def normalize_severity(value):
    if not value:
        return "info"

    value = str(value).lower().strip()

    valid_levels = ["critical", "high", "medium", "low", "info"]

    if value in valid_levels:
        return value

    return "info"


def classify_severity(finding):
    """
    This function makes sure severity never becomes blank.

    First, it uses Nuclei's own severity if Nuclei provides one.
    If Nuclei only gives 'info', it estimates the severity based on the finding text.
    """

    native_severity = normalize_severity(
        finding.get("info", {}).get("severity", "info")
    )

    # Trust Nuclei if it already provides useful severity.
    if native_severity in ["critical", "high", "medium", "low"]:
        return native_severity

    matcher_name = finding.get("matcher-name", "")
    template_id = finding.get("template-id", "")
    template_name = finding.get("info", {}).get("name", "")
    description = finding.get("info", {}).get("description", "")

    text = f"{matcher_name} {template_id} {template_name} {description}".lower()

    critical_keywords = [
        "remote code execution",
        "rce",
        "command injection",
        "sql injection",
        "sqli",
        "authentication bypass",
        "unauthenticated admin",
        "default admin credential",
        "critical"
    ]

    high_keywords = [
        "strict-transport-security",
        "hsts",
        "content-security-policy",
        "csp",
        "frame-ancestors",
        "cors misconfiguration",
        "wildcard cors",
        "open cors",
        "access-control-allow-origin: *",
        "exposed secret",
        "api key",
        "private key",
        "password disclosure",
        "token disclosure",
        "directory traversal",
        "path traversal",
        "server-side request forgery",
        "ssrf",
        "high"
    ]

    medium_keywords = [
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "feature-policy",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "cross-origin-embedder-policy",
        "x-permitted-cross-domain-policies",
        "clear-site-data",
        "origin-agent-cluster",
        "clickjacking",
        "mime sniffing",
        "missing security header",
        "open redirect",
        "directory listing",
        "medium"
    ]

    low_keywords = [
        "x-xss-protection",
        "x-download-options",
        "x-dns-prefetch-control",
        "expect-ct",
        "nel",
        "report-to",
        "reporting-endpoints",
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "powered-by",
        "technology disclosure",
        "information disclosure",
        "cache-control",
        "pragma",
        "expires",
        "low"
    ]

    info_keywords = [
        "robots.txt",
        "sitemap.xml",
        "favicon",
        "waf detect",
        "cdn detect",
        "technology detect",
        "http title",
        "tls",
        "ssl",
        "whois",
        "dns",
        "fingerprint",
        "info"
    ]

    for keyword in critical_keywords:
        if keyword in text:
            return "critical"

    for keyword in high_keywords:
        if keyword in text:
            return "high"

    for keyword in medium_keywords:
        if keyword in text:
            return "medium"

    for keyword in low_keywords:
        if keyword in text:
            return "low"

    for keyword in info_keywords:
        if keyword in text:
            return "info"

    # Final backup: never blank
    return native_severity or "info"


def build_severity_data(findings):
    severity_count = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:
        level = normalize_severity(finding.get("display_severity", "info"))

        if level in severity_count:
            severity_count[level] += 1
        else:
            severity_count["info"] += 1

    total = len(findings)

    severity_data = []

    for level in ["critical", "high", "medium", "low", "info"]:
        count = severity_count[level]
        percent = int((count / total) * 100) if total > 0 else 0

        severity_data.append({
            "level": level,
            "count": count,
            "percent": percent
        })

    return severity_data


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["target"]

    os.makedirs(RESULTS_DIR, exist_ok=True)

    output_filename = f"output_{int(time.time())}.jsonl"
    output = os.path.join(RESULTS_DIR, output_filename)

    cmd = [
        "nuclei",
        "-u", target,
        "-t", "/root/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",
        "-jsonl",
        "-o", output,
        "-c", "1",
        "-rl", "1",
        "-timeout", "10",
        "-retries", "0",
        "-silent",
        "-duc"
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
    except Exception as e:
        return f"Scan error: {e}"

    findings = []

    if os.path.exists(output):
        with open(output, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        finding = json.loads(line)

                        display_severity = classify_severity(finding)
                        finding["display_severity"] = display_severity

                        findings.append(finding)

                    except json.JSONDecodeError:
                        pass

    severity_data = build_severity_data(findings)

    return render_template(
        "index.html",
        target=target,
        findings=findings,
        stderr=r.stderr,
        output_file=output_filename,
        severity_data=severity_data
    )


@app.route("/download/<filename>")
def download_result(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(RESULTS_DIR, safe_filename, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
