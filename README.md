# HTTPS Certificate Validation and Website Security Checker

A college-level Flask project for inspecting HTTPS certificates and selected website security settings. The responsive dashboard submits scans to the Flask API and displays the checks returned by the certificate, TLS, redirect, and header inspection modules.

## Requirements

- Python 3.10 or newer
- pip

## Set up on Windows (PowerShell)

From the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell prevents environment activation, either use a permitted activation method for your machine or invoke the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the application

```powershell
python app.py
```

Open the local address printed by Flask in your browser. Enter an HTTP(S) URL and choose **Scan website**. The browser sends a JSON `POST` to `/api/scan`; invalid input and server/network errors are shown in the page.

## Run tests

```powershell
python -m pytest
```

## Project structure

```text
.
├── app.py
├── requirements.txt
├── README.md
├── tests/
│   ├── test_app.py
│   ├── test_certificate_inspection.py
│   ├── test_routes.py
│   └── test_stage_three_inspection.py
└── webchecker/
    ├── __init__.py
    ├── routes.py
    ├── check_results.py
    ├── url_validation.py
    ├── certificate_inspection.py
    ├── tls_inspection.py
    ├── header_checks.py
    ├── report.py
    ├── templates/
    │   └── index.html
    └── static/
        ├── css/
        │   └── styles.css
        └── js/
            └── app.js
```

## Planned functionality and limitations

The Flask `POST /api/scan` endpoint validates the submitted URL, runs the inspection modules and returns a JSON report. The responsive dashboard displays the returned overall status, individual findings, certificate issuer and dates, negotiated TLS information, redirect/header results, and available recommendations. UI values are rendered as text rather than interpreted as HTML. Missing headers use `WARNING` and remain separate from certificate validity and trust results. The HTTP-to-HTTPS finding tests the server's actual redirect chain and includes its final URL; it does not emulate browser HSTS preload behavior.

Network checks accept only HTTP(S) URLs without credentials, reject DNS answers that include non-public IP destinations, pin each request to a validated public IP address, disable environment proxies, and revalidate every redirect. TLS verification remains enabled. HTTP responses are requested as streams and bodies are not downloaded; redirects, timeouts and response metadata are bounded.

The scanner does not persist results. DNS resolution uses the operating system resolver, whose lookup time is outside the socket connection timeout. A valid certificate does not prove a site is legitimate or phishing-free. The TLS version and cipher are the negotiated values from one connection, not a complete inventory of server-supported configurations. These checks are educational indicators, not a guarantee of overall website security.
