"""
SOC Threat Monitoring Dashboard + Real IP Lookup — Combined App
-----------------------------------------------------------------
One Flask app that:
  1. Serves the SOC dashboard UI (simulated live feed, charts, alert table)
  2. Provides a REAL IP lookup panel wired to AbuseIPDB + VirusTotal APIs

Run:
    pip install -r requirements.txt
    export ABUSEIPDB_API_KEY="your_key_here"     # required for real data
    export VT_API_KEY="your_key_here"            # optional
    python app.py

Open: http://127.0.0.1:5000/
"""

import os
import re
import ipaddress
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")

IP_REGEX = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def is_valid_ip(ip: str) -> bool:
    m = IP_REGEX.match(ip)
    if not m:
        return False
    return all(0 <= int(part) <= 255 for part in m.groups())


def classify_local_ip(ip: str):
    """
    Detects private / local-network / reserved IPs (routers, phones,
    laptops, cameras, and other devices on a home or office LAN, plus
    loopback and link-local addresses). Public geo/threat-intel services
    cannot look these up — they only know about public internet IPs — so
    instead of returning an error, we explain what the address range means.
    Returns a dict describing the range if it's non-public, else None.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    if addr.is_loopback:
        return {
            "kind": "Loopback address",
            "explanation": "This refers to the device itself (localhost) — "
                            "it always points back to the computer or phone "
                            "that is making the request, never to a device "
                            "on the network."
        }
    if addr.is_link_local:
        return {
            "kind": "Link-local address",
            "explanation": "This is an auto-assigned address used only for "
                            "direct communication on the same physical network "
                            "segment (common when a device couldn't get an "
                            "address from a router/DHCP). It is not routable "
                            "on the internet."
        }
    if addr.is_private:
        # Try to guess the device role from common conventions
        octets = str(addr).split(".")
        guess = "a device on this local network (phone, laptop, camera, smart TV, etc.)"
        if str(addr).endswith(".1") or str(addr).endswith(".254"):
            guess = "very likely the router / gateway of this local network"
        return {
            "kind": "Private (LAN) address",
            "explanation": f"This is a private IP address used inside a home "
                            f"or office network (ranges like 10.x.x.x, "
                            f"172.16–31.x.x, or 192.168.x.x). It is {guess}. "
                            f"Private IPs are never visible on the public "
                            f"internet, so there is no public geolocation, "
                            f"ISP, or abuse-report data for them — that's "
                            f"expected, not an error. To identify the exact "
                            f"device, check your router's connected-devices "
                            f"list or the device's own network settings."
        }
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return {
            "kind": "Reserved / special-use address",
            "explanation": "This address is reserved for special networking "
                            "purposes (e.g. multicast or protocol reserved "
                            "ranges) and is not assigned to a regular public "
                            "or home-network device."
        }
    return None


def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"available": False, "reason": "ABUSEIPDB_API_KEY not set on server"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=8)
        if resp.status_code == 401:
            return {"available": False, "reason": "Invalid AbuseIPDB API key"}
        if resp.status_code == 429:
            return {"available": False, "reason": "AbuseIPDB daily limit reached"}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "available": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "usage_type": data.get("usageType"),
            "last_reported_at": data.get("lastReportedAt"),
        }
    except requests.RequestException as e:
        return {"available": False, "reason": f"AbuseIPDB request error: {e}"}


def check_virustotal(ip: str) -> dict:
    if not VT_API_KEY:
        return {"available": False, "reason": "VT_API_KEY not set on server"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 401:
            return {"available": False, "reason": "Invalid VirusTotal API key"}
        if resp.status_code == 429:
            return {"available": False, "reason": "VirusTotal rate limit reached"}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "available": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "as_owner": attrs.get("as_owner"),
        }
    except requests.RequestException as e:
        return {"available": False, "reason": f"VirusTotal request error: {e}"}


def check_ip_geo(ip: str) -> dict:
    """
    Free, no-API-key-required lookup (ip-api.com) for basic real info:
    country, region, city, ISP, org, ASN, and proxy/hosting/mobile flags.
    This ALWAYS works even if AbuseIPDB/VirusTotal keys are not configured,
    so the user gets real information about the IP no matter what.
    """
    url = f"http://ip-api.com/json/{ip}"
    params = {"fields": "status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query"}
    try:
        resp = requests.get(url, params=params, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return {"available": False, "reason": data.get("message", "lookup failed")}
        return {
            "available": True,
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "is_proxy_or_vpn": data.get("proxy"),
            "is_hosting_datacenter": data.get("hosting"),
            "is_mobile": data.get("mobile"),
        }
    except requests.RequestException as e:
        return {"available": False, "reason": f"geo lookup error: {e}"}


def classify_severity(abuse: dict, vt: dict) -> str:
    score = abuse.get("abuse_confidence_score") or 0
    malicious = vt.get("malicious") or 0
    if score >= 75 or malicious >= 5:
        return "critical"
    if score >= 40 or malicious >= 1:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/lookup", methods=["GET"])
def lookup():
    ip = request.args.get("ip", "").strip()
    if not ip or not is_valid_ip(ip):
        return jsonify({"error": "Please provide a valid IPv4 address, e.g. ?ip=8.8.8.8"}), 400

    try:
        local_info = classify_local_ip(ip)

        # Private / loopback / reserved addresses: public services can't
        # look these up, so return a clear, friendly explanation instead
        # of calling external APIs (which would just fail with an error).
        if local_info:
            return jsonify({
                "ip": ip,
                "severity": "low",
                "is_local": True,
                "local_info": local_info,
                "geo": {"available": False, "reason": "Not applicable — this is a private/local address, not a public internet address."},
                "abuseipdb": {"available": False, "reason": "Not applicable for private/local addresses."},
                "virustotal": {"available": False, "reason": "Not applicable for private/local addresses."},
            })

        geo_result = check_ip_geo(ip)
        abuse_result = check_abuseipdb(ip)
        vt_result = check_virustotal(ip)
        severity = classify_severity(abuse_result, vt_result)

        return jsonify({
            "ip": ip,
            "severity": severity,
            "is_local": False,
            "geo": geo_result,
            "abuseipdb": abuse_result,
            "virustotal": vt_result,
        })
    except Exception as e:
        # Safety net: never let an unexpected error surface as a raw 500 —
        # always return a clear, readable JSON message instead.
        return jsonify({
            "ip": ip,
            "severity": "low",
            "is_local": False,
            "geo": {"available": False, "reason": f"Lookup temporarily failed: {e}"},
            "abuseipdb": {"available": False, "reason": "Skipped due to earlier error."},
            "virustotal": {"available": False, "reason": "Skipped due to earlier error."},
        })


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "abuseipdb_configured": bool(ABUSEIPDB_API_KEY),
        "virustotal_configured": bool(VT_API_KEY),
    })


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "Not Found — this route does not exist on the server.",
        "hint": "Check the URL. The dashboard is at '/' and the lookup API is at '/api/lookup?ip=1.2.3.4'."
    }), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({
        "error": "The server hit an unexpected problem while processing this request. Please try again."
    }), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
