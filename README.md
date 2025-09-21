# Web-sec-scanner-chrome-extension-version

A lightweight Chrome extension that helps developers quickly check the security posture of websites while browsing.

Features:
Detects if HTTPS is enforced
Highlights missing security headers (e.g., CSP, HSTS, Referrer Policy)
Checks for presence of robots.txt
Detects directory listing exposure
Scans for cookie flags (Secure / HttpOnly / SameSite)
Identifies mixed content issues

Provides results in two modes:
Raw JSON output
Readable UI explanation (developer-friendly)

Why no Nmap, Nikto, or Subdomain Enumeration?
Browser sandbox limitations → Extensions cannot run system-level binaries.
Performance → Heavy scans would slow down browsing.
Security & legal reasons → Chrome Web Store rejects intrusive scanning tools.
Focus → Fast, passive checks for developers without risk.
This makes the extension safe, fast, and practical for everyday use.

Tech Stack
JavaScript (Chrome Extension APIs)
HTML/CSS for popup UI
