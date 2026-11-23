import logging

from flask import Blueprint, jsonify, render_template, request

from webchecker.certificate_inspection import inspect_certificate
from webchecker.header_checks import inspect_headers
from webchecker.report import build_scan_report
from webchecker.tls_inspection import negotiated_tls
from webchecker.url_validation import URLValidationError, validate_url


main = Blueprint("main", __name__)
logger = logging.getLogger(__name__)


@main.get("/")
def index():
    return render_template("index.html")


@main.post("/api/scan")
def scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
        return jsonify({"error": "Submit a JSON object with a URL string."}), 400

    url = payload["url"]
    try:
        target = validate_url(url)
    except URLValidationError as error:
        return jsonify({"error": str(error)}), 400

    certificate_port = target.port if target.scheme == "https" else 443
    certificate = inspect_certificate(target.hostname, port=certificate_port)
    tls = negotiated_tls(certificate)
    headers = inspect_headers(target.url)

    logger.info("Website inspection completed.")
    return jsonify(build_scan_report(url, certificate, tls, headers))
