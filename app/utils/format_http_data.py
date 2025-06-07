"""
Module: http_transformer.py

Reads raw HTTP records from a JSON file, transforms each record into the
HttpActivity shape (matching the frontend mockData.ts), and writes out
a JSON file ready for consumption by the frontend.
"""

import uuid
import datetime
import logging
import json
import re
from typing import Optional, Dict, Any, Union, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECURITY_HEADER_MAP = {
    "missing_csp": "Content-Security-Policy",
    "missing_hsts": "Strict-Transport-Security",
    "missing_xcto": "X-Content-Type-Options",
    "missing_xfo": "X-Frame-Options",
    "missing_xxp": "X-XSS-Protection",
    "missing_rp": "Referrer-Policy",
}

# Regex to match the HTTP status line (HTTP/1.x, HTTP/2, etc.)
STATUS_LINE_RE = re.compile(rb"^HTTP/\d+\.\d+\s+(\d{3})\b")


def _parse_status_code(raw: Union[bytes, str]) -> Optional[int]:
    """
    Parse the HTTP status code from a raw HTTP response string or bytes.
    Returns the integer code (e.g. 404) or None if it can't find one.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("iso-8859-1", errors="ignore")
    else:
        raw_bytes = raw

    # Extract the first line
    first_line, *_ = (
        raw_bytes.split(b"\r\n", 1)
        if b"\r\n" in raw_bytes
        else raw_bytes.split(b"\n", 1)
    )

    match = STATUS_LINE_RE.match(first_line)
    if not match:
        return None
    try:
        return int(match.group(1))
    except (ValueError, TypeError):
        return None


def transform_http_activity(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform a single raw HTTP record into the HttpActivity shape.
    """
    # Generate a unique ID for front-end tracking
    activity_id = f"http-{uuid.uuid4()}"

    # Convert timestamp to ISO8601 Zulu
    dt = datetime.datetime.fromisoformat(rec["timestamp"])
    timestamp = (
        dt.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )

    # Missing security headers
    sec = rec.get("header_analysis", {}).get("security_headers", {})
    missing_headers = [
        SECURITY_HEADER_MAP[key]
        for key, present in sec.items()
        if present and key in SECURITY_HEADER_MAP
    ]

    # Injection detection
    header_inj = bool(rec.get("header_analysis", {}).get("injection_vectors"))
    content = rec.get("content_analysis", {})
    content_inj = bool(
        content.get("injection_patterns") or content.get("malicious_payloads")
    )
    injection_detected = header_inj or content_inj

    # Beaconing indicators
    beh = rec.get("behavioral_indicators", {})
    beaconing_indicators = bool(
        beh.get("beaconing") or beh.get("unusual_timing", {}).get("beaconing_pattern")
    )

    # Status code extraction
    status_code = None
    raw_resp = rec.get("raw_response")
    if raw_resp is not None:
        status_code = _parse_status_code(raw_resp)
        if status_code is None:
            logger.warning(
                f"Unable to parse status code from raw_response: {raw_resp!r}"
            )
    else:
        logger.debug("Record has no 'raw_response'; setting statusCode=None.")

    # Threat score
    threat_score = rec.get("threat_analysis", {}).get("threat_score")

    return {
        "id": activity_id,
        "timestamp": timestamp,
        "sourceIp": rec.get("source_ip"),
        "destinationIp": rec.get("destination_ip"),
        "method": rec.get("method"),
        "path": rec.get("path"),
        "statusCode": status_code,
        "userAgent": rec.get("user_agent"),
        "referrer": rec.get("referer"),
        "contentType": rec.get("content_type"),
        "missingSecurityHeaders": missing_headers,
        "injectionDetected": injection_detected,
        "beaconingIndicators": beaconing_indicators,
        "threatScore": threat_score,
    }


def transform_batch(input_file: str, output_file: str) -> None:
    """
    Read raw HTTP records from input_file (JSON array), transform each, and write
    out to output_file in the shape:

    {
        "httpActivities": [ ... transformed records ... ]
    }
    """
    with open(input_file, "r", encoding="utf-8") as f:
        raw_list = json.load(f)
        if not isinstance(raw_list, list):
            logger.error(f"Expected a list of HTTP records in {input_file}")
            return

    transformed: List[Dict[str, Any]] = []
    for rec in raw_list:
        transformed.append(transform_http_activity(rec))

    output = {"httpActivities": transformed}
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    logger.info(f"Wrote {len(transformed)} activities to {output_file}")


# if __name__ == "__main__":
#     import argparse

#     parser = argparse.ArgumentParser(
#         description="Transform raw HTTP data to frontend-ready activities"
#     )
#     parser.add_argument(
#         "--in",
#         dest="input_file",
#         required=True,
#         help="Path to raw HTTP JSON log (e.g. http_data_log.json)",
#     )
#     parser.add_argument(
#         "--out",
#         dest="output_file",
#         required=True,
#         help="Path to write transformed data (e.g. frontend_data.json)",
#     )
#     args = parser.parse_args()

#     transform_batch(args.input_file, args.output_file)
