from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import re

app = Flask(__name__)
CORS(app)


# =========================================================
# NMAP SCANNING
# =========================================================

def parse_nmap_output(target):
    """Run Nmap and return detected open ports."""

    try:
        result = subprocess.run(
            ["nmap", "-p-", "--open", "-sV", target],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            return None, result.stderr.strip()

        ports = []

        for line in result.stdout.splitlines():

            match = re.match(
                r"^(\d+)/(\w+)\s+(\w+)\s+(.+)$",
                line.strip()
            )

            if match:
                port, protocol, state, service = match.groups()

                ports.append({
                    "port": int(port),
                    "protocol": protocol,
                    "state": state,
                    "service": service.strip()
                })

        return ports, None

    except subprocess.TimeoutExpired:
        return None, "Nmap scan timed out."

    except Exception as e:
        return None, str(e)


# =========================================================
# SECURITY ANALYSIS
# =========================================================

def analyze_port(port):
    """
    Determine the security risk of an open port.
    """

    high_risk_ports = {
        21: "FTP can transmit credentials without encryption.",
        23: "Telnet is insecure and transmits credentials in plaintext.",
        445: "SMB should not normally be exposed unnecessarily.",
        3389: "RDP can be a high-value target for remote attacks.",
        3306: "MySQL should normally be restricted to trusted hosts.",
        1433: "Microsoft SQL Server should be restricted to trusted hosts.",
        1521: "Oracle Database should be restricted to trusted hosts.",
        5432: "PostgreSQL should be restricted to trusted hosts."
    }

    medium_risk_ports = {
        22: "SSH should use strong authentication and restricted access.",
        25: "SMTP may be abused if improperly configured.",
        53: "DNS services should be properly restricted.",
        80: "HTTP traffic is unencrypted; HTTPS is preferable.",
        110: "POP3 may transmit email credentials without encryption.",
        139: "NetBIOS/SMB services can expose network information.",
        143: "IMAP should preferably use encrypted connections.",
        5000: "A web application is exposed on this port.",
        8080: "An HTTP application is exposed on this port."
    }

    low_risk_ports = {
        443: "HTTPS is encrypted but should still be securely configured.",
        3000: "A development web application may be running.",
        8443: "An HTTPS application is exposed on an alternate port."
    }

    if port in high_risk_ports:
        return {
            "level": "HIGH",
            "reason": high_risk_ports[port]
        }

    if port in medium_risk_ports:
        return {
            "level": "MEDIUM",
            "reason": medium_risk_ports[port]
        }

    if port in low_risk_ports:
        return {
            "level": "LOW",
            "reason": low_risk_ports[port]
        }

    return {
        "level": "LOW",
        "reason": "No specific high-risk service rule was identified."
    }


def analyze_security(ports):
    """
    Analyze all detected ports and generate a security summary.
    """

    high = 0
    medium = 0
    low = 0

    analyzed_ports = []
    recommendations = []

    for port_info in ports:

        port_number = port_info["port"]

        analysis = analyze_port(port_number)

        risk_level = analysis["level"]

        if risk_level == "HIGH":
            high += 1

        elif risk_level == "MEDIUM":
            medium += 1

        else:
            low += 1

        analyzed_port = {
            **port_info,
            "risk": risk_level,
            "risk_reason": analysis["reason"]
        }

        analyzed_ports.append(analyzed_port)

        # Add recommendation for high-risk services
        if risk_level == "HIGH":
            recommendations.append({
                "port": port_number,
                "risk": "HIGH",
                "message": analysis["reason"]
            })

        # Add recommendation for medium-risk services
        elif risk_level == "MEDIUM":
            recommendations.append({
                "port": port_number,
                "risk": "MEDIUM",
                "message": analysis["reason"]
            })

    # Determine overall risk
    if high > 0:
        overall_risk = "HIGH"

    elif medium > 0:
        overall_risk = "MEDIUM"

    else:
        overall_risk = "LOW"

    return {
        "risk_level": overall_risk,
        "high": high,
        "medium": medium,
        "low": low,
        "total_open_ports": len(ports),
        "recommendations": recommendations,
        "ports": analyzed_ports
    }


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "message": "Port Scanner Backend is running!"
    })


# =========================================================
# SCAN
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json(silent=True) or {}

        target = data.get("target", "").strip()

        if not target:

            return jsonify({
                "error": "Target is required."
            }), 400

        # Run Nmap
        ports, error = parse_nmap_output(target)

        if error:

            return jsonify({
                "error": error
            }), 500

        # Perform security analysis
        security = analyze_security(ports)

        return jsonify({

            "target": target,

            "status": "success",

            "ports": ports,

            "security": {

                "risk_level": security["risk_level"],

                "high": security["high"],

                "medium": security["medium"],

                "low": security["low"],

                "total_open_ports": security["total_open_ports"],

                "recommendations": security["recommendations"]

            },

            "analyzed_ports": security["ports"]

        }), 200

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok"
    }), 200


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )