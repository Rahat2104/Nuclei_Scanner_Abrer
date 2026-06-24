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


def generate_ai_explanation(finding):
    """
    Local AI-style explanation generator.
    It explains each finding in simple language without requiring an external API key.
    """

    header = finding.get("matcher-name", "").lower().strip()
    severity = finding.get("display_severity", "info")
    template_name = finding.get("info", {}).get("name", "Security finding")
    description = finding.get("info", {}).get("description", "")

    explanations = {
        "strict-transport-security": {
            "meaning": "The website is missing the Strict-Transport-Security header. This header tells browsers to only use HTTPS when connecting to the site.",
            "risk": "Without it, users may be more exposed to protocol downgrade attacks or insecure HTTP connections.",
            "fix": "Add the Strict-Transport-Security header with a safe max-age value after confirming HTTPS works correctly across the site."
        },
        "content-security-policy": {
            "meaning": "The website is missing a Content-Security-Policy header. CSP helps control which scripts, styles, images, and resources the browser is allowed to load.",
            "risk": "Without CSP, the site may have weaker protection against cross-site scripting and content injection attacks.",
            "fix": "Create a Content-Security-Policy that only allows trusted sources for scripts, styles, images, frames, and connections."
        },
        "x-frame-options": {
            "meaning": "The website is missing the X-Frame-Options header. This header helps prevent the page from being embedded inside a malicious frame.",
            "risk": "Without it, the site may be more exposed to clickjacking attacks.",
            "fix": "Add X-Frame-Options with DENY or SAMEORIGIN, or use the frame-ancestors directive in Content-Security-Policy."
        },
        "x-content-type-options": {
            "meaning": "The website is missing the X-Content-Type-Options header. This header prevents browsers from guessing file types incorrectly.",
            "risk": "Without it, browsers may perform MIME sniffing, which can increase the risk of unwanted script execution in some cases.",
            "fix": "Add X-Content-Type-Options with the value nosniff."
        },
        "referrer-policy": {
            "meaning": "The website is missing the Referrer-Policy header. This header controls how much referrer information is shared when users click links.",
            "risk": "Without it, sensitive URL information may be leaked to third-party websites.",
            "fix": "Add a Referrer-Policy such as strict-origin-when-cross-origin or no-referrer depending on the application requirement."
        },
        "permissions-policy": {
            "meaning": "The website is missing the Permissions-Policy header. This header controls access to browser features such as camera, microphone, geolocation, and sensors.",
            "risk": "Without it, the browser may allow more features than the site actually needs.",
            "fix": "Add a Permissions-Policy header and disable browser features that are not required."
        },
        "cross-origin-opener-policy": {
            "meaning": "The website is missing the Cross-Origin-Opener-Policy header. This header helps isolate browsing contexts between different origins.",
            "risk": "Without it, the site may have weaker protection against cross-origin interaction risks.",
            "fix": "Add Cross-Origin-Opener-Policy with a value such as same-origin if compatible with the application."
        },
        "cross-origin-resource-policy": {
            "meaning": "The website is missing the Cross-Origin-Resource-Policy header. This header controls whether other origins can load the site's resources.",
            "risk": "Without it, resources may be more easily shared or embedded across origins.",
            "fix": "Add Cross-Origin-Resource-Policy with a suitable value such as same-origin, same-site, or cross-origin depending on the use case."
        },
        "cross-origin-embedder-policy": {
            "meaning": "The website is missing the Cross-Origin-Embedder-Policy header. This header helps control how cross-origin resources are embedded.",
            "risk": "Without it, the site may not benefit from stronger browser isolation features.",
            "fix": "Add Cross-Origin-Embedder-Policy after confirming that required third-party resources still load correctly."
        },
        "x-permitted-cross-domain-policies": {
            "meaning": "The website is missing the X-Permitted-Cross-Domain-Policies header. This header controls how Adobe products handle cross-domain policy files.",
            "risk": "Without it, old clients may allow cross-domain data access in ways the site owner did not intend.",
            "fix": "Add X-Permitted-Cross-Domain-Policies with a restrictive value such as none."
        }
    }

    if header in explanations:
        item = explanations[header]
        return (
            f"{item['meaning']} "
            f"Risk level: {severity.upper()}. "
            f"{item['risk']} "
            f"Recommended fix: {item['fix']}"
        )

    if header:
        return (
            f"This finding is related to {header}. "
            f"Risk level: {severity.upper()}. "
            f"Nuclei detected this as part of the scan result. "
            f"Review the finding details and apply the recommended security configuration for this item."
        )

    return (
        f"This result was detected by the template '{template_name}'. "
        f"Risk level: {severity.upper()}. "
        f"{description if description else 'Review the finding and confirm whether it affects the target application.'}"
    )


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

    # Default lightweight template from Nuclei
    "-t", "/root/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml",

    # My additional custom lightweight template
    "-t", "scanner-templates/basic-http-check.yaml",

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

                        ai_explanation = generate_ai_explanation(finding)
                        finding["ai_explanation"] = ai_explanation

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
