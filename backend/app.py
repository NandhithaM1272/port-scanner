from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

import subprocess
import re
import time
import os
import json
import smtplib


from email.message import EmailMessage

from datetime import datetime, timezone
from dotenv import load_dotenv




# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

print("EMAIL_ADDRESS:", EMAIL_ADDRESS)
print("EMAIL_PASSWORD configured:", bool(EMAIL_PASSWORD))

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "SUPABASE_URL and SUPABASE_KEY must be configured in .env"
    )


# ============================================================
# CONFIGURATION
# ============================================================

NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"



# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "http://localhost:3000",
                "http://127.0.0.1:3000"
            ]
        }
    }
)


# ============================================================
# SUPABASE CLIENT
# ============================================================

supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)


# ============================================================
# RISK ANALYSIS
# ============================================================

def analyze_port(port, service, protocol="tcp"):

    service_lower = service.lower()
    protocol_lower = protocol.lower()

    # ========================================================
    # HIGH-RISK TCP PORTS
    # ========================================================

    high_risk_ports = {
        21: "FTP can transmit credentials without encryption.",
        23: "Telnet is insecure and should generally not be exposed.",
        445: "SMB should not normally be exposed unnecessarily.",
        3389: "RDP should normally be restricted to trusted hosts.",
        3306: "MySQL should normally be restricted to trusted hosts.",
        1433: "Microsoft SQL Server should normally be restricted.",
        1521: "Oracle Database should normally be restricted.",
        5432: "PostgreSQL should normally be restricted to trusted hosts."
    }

    # ========================================================
    # HIGH-RISK UDP PORTS
    # ========================================================

    high_risk_udp_ports = {
        161: "SNMP service detected.",
        69: "TFTP service detected. TFTP does not provide encryption."
    }

    # ========================================================
    # MEDIUM-RISK TCP PORTS
    # ========================================================

    medium_risk_ports = {
        22: "SSH is exposed and should be restricted to trusted users.",
        80: "HTTP traffic is unencrypted.",
        8080: "A web application is exposed on this port.",
        8000: "A development web application may be running.",
        3000: "A development web application may be running.",
        5000: "A web application or API is exposed on this port.",
        8443: "An HTTPS web application is exposed on this port."
    }

    # ========================================================
    # MEDIUM-RISK UDP PORTS
    # ========================================================

    medium_risk_udp_ports = {
        53: "DNS service detected.",
        123: "NTP service detected."
    }

    # ========================================================
    # UDP RISK ANALYSIS
    # ========================================================

    if protocol_lower == "udp":

        if port in high_risk_udp_ports:
            return (
                "HIGH",
                high_risk_udp_ports[port]
            )

        if port in medium_risk_udp_ports:
            return (
                "MEDIUM",
                medium_risk_udp_ports[port]
            )

    # ========================================================
    # TCP PORT RISK ANALYSIS
    # ========================================================

    if protocol_lower == "tcp":

        if port in high_risk_ports:
            return (
                "HIGH",
                high_risk_ports[port]
            )

        if port in medium_risk_ports:
            return (
                "MEDIUM",
                medium_risk_ports[port]
            )

    # ========================================================
    # SERVICE-BASED RULES
    # ========================================================

    if "ftp" in service_lower:

        return (
            "HIGH",
            "FTP service detected. Credentials may be transmitted insecurely."
        )

    if "telnet" in service_lower:

        return (
            "HIGH",
            "Telnet service detected. Telnet is insecure."
        )

    if "mysql" in service_lower:

        return (
            "HIGH",
            "MySQL should normally be restricted to trusted hosts."
        )

    if "microsoft-ds" in service_lower or "smb" in service_lower:

        return (
            "HIGH",
            "SMB should not normally be exposed unnecessarily."
        )

    if "rdp" in service_lower:

        return (
            "HIGH",
            "Remote Desktop services should normally be restricted."
        )

    if "http" in service_lower:

        return (
            "MEDIUM",
            "A web application is exposed on this port."
        )

    # ========================================================
    # DEFAULT
    # ========================================================

    return (
        "LOW",
        "No specific high-risk service rule was identified."
    )


#===========================================================
# VALIDATE CUSTOM PORTS
#===========================================================

def validate_custom_ports(custom_ports):
    """
    Validate custom Nmap port input.

    Allowed:
        80
        80,443,3306
        20-25
        22,80,443,3000-3010
    """

    # Convert the received value to text
    if custom_ports is None:
        return False, "Please enter at least one custom port."

    custom_ports = str(custom_ports).strip()

    if not custom_ports:
        return False, "Please enter at least one custom port."

    # Only allow numbers, commas, hyphens and spaces
    if not re.fullmatch(r"[0-9,\-\s]+", custom_ports):
        return False, (
            "Invalid port format. Use examples like "
            "80, 80,443, or 20-25"
        )

    parts = custom_ports.split(",")

    for part in parts:

        part = part.strip()

        if not part:
            return False, "Invalid comma placement in custom ports."

        # Port range
        if "-" in part:

            range_parts = part.split("-")

            if len(range_parts) != 2:
                return False, f"Invalid port range: {part}"

            try:
                start_port = int(range_parts[0].strip())
                end_port = int(range_parts[1].strip())

            except ValueError:
                return False, f"Invalid port range: {part}"

            if not (1 <= start_port <= 65535):
                return False, f"Invalid port: {start_port}"

            if not (1 <= end_port <= 65535):
                return False, f"Invalid port: {end_port}"

            if start_port > end_port:
                return False, (
                    f"Invalid range: {part}. "
                    "Start port must be smaller than end port."
                )

        # Single port
        else:

            try:
                port = int(part)

            except ValueError:
                return False, f"Invalid port: {part}"

            if not (1 <= port <= 65535):
                return False, f"Invalid port: {port}"

    return True, custom_ports



# ============================================================
# NMAP SCANNER
# ============================================================

def parse_nmap_output(
    target,
    scan_type="Full TCP",
    custom_ports=None,
    timing="T3"
):
    try:

        # ====================================================
        # VALID TIMING LEVELS
        # ====================================================

        allowed_timings = [
            "T0",
            "T1",
            "T2",
            "T3",
            "T4",
            "T5"
        ]

        if timing not in allowed_timings:
            return (
                None,
                "Invalid timing. Choose T0, T1, T2, T3, T4 or T5.",
                0
            )

        # ====================================================
        # QUICK TCP SCAN
        # ====================================================

        if scan_type == "Quick TCP":

            nmap_args = [
                NMAP_PATH,
                f"-{timing}",
                "--top-ports",
                "1000",
                "--open",
                "-sV",
                target
            ]

        # ====================================================
        # FULL TCP SCAN
        # ====================================================

        elif scan_type == "Full TCP":

            nmap_args = [
                NMAP_PATH,
                f"-{timing}",
                "-p-",
                "--open",
                "-sV",
                target
            ]

        # ====================================================
        # UDP SCAN
        # ====================================================

        elif scan_type == "UDP":

            nmap_args = [
                NMAP_PATH,
                f"-{timing}",
                "-sU",
                "--top-ports",
                "100",
                "--open",
                "-sV",
                target
            ]

        # ====================================================
        # AGGRESSIVE SCAN
        # ====================================================

        elif scan_type == "Aggressive":

            nmap_args = [
                NMAP_PATH,
                f"-{timing}",
                "-A",
                "--open",
                target
            ]

        # ====================================================
        # CUSTOM PORTS SCAN
        # ====================================================

        elif scan_type == "Custom Ports":

            valid, result = validate_custom_ports(custom_ports)

            if not valid:
                return None, result, 0

            custom_ports = result

            nmap_args = [
                NMAP_PATH,
                f"-{timing}",
                "-p",
                custom_ports,
                "--open",
                "-sV",
                target
            ]

        # ====================================================
        # VERBOSITY SCAN
        # ====================================================
        elif scan_type == "Verbosity Scan":

            allowed_timings = [
                "T0",
                "T1",
                "T2",
                "T3",
                "T4",
                "T5"
            ]

            if timing not in allowed_timings:
                return (
                    None,
                    "Invalid timing. Choose T0, T1, T2, T3, T4 or T5.",
                    0
                )

            nmap_args = [
                NMAP_PATH,
                f"-{timing}",
                "-p-",
                "--open",
                "-sV",
                "-v",
                target
            ]

        # ====================================================
        # UNKNOWN SCAN TYPE
        # ====================================================

        else:

            return (
                None,
                "Invalid scan type.",
                0
            )

        # ====================================================
        # DEBUG
        # ====================================================

        print("========================================")
        print("NMAP SCAN")
        print("========================================")
        print("Target:", target)
        print("Scan Type:", scan_type)
        print("Timing:", timing)
        print("Command:", nmap_args)
        print("========================================")

        # ====================================================
        # START TIMER
        # ====================================================

        scan_start = time.perf_counter()

        result = subprocess.run(
            nmap_args,
            capture_output=True,
            text=True,
            timeout=600
        )

        scan_duration = round(
            time.perf_counter() - scan_start,
            2
        )

        # ====================================================
        # NMAP ERROR
        # ====================================================

        if result.returncode != 0:

            error_message = result.stderr.strip()

            if not error_message:
                error_message = result.stdout.strip()

            return (
                None,
                error_message,
                scan_duration
            )

        # ====================================================
        # PARSE OPEN PORTS
        # ====================================================

        ports = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            match = re.match(
                r"^(\d+)\/(tcp|udp)\s+(\w+)\s+(.+)$",
                line,
                re.IGNORECASE
            )

            if not match:
                continue

            port, protocol, state, service = match.groups()

            port_number = int(port)

            protocol = protocol.lower()

            state = state.lower()

            service = service.strip()

            if state != "open":
                continue

            # =================================================
            # RISK ANALYSIS
            # =================================================

            risk, risk_reason = analyze_port(
                port_number,
                service,
                protocol
            )

            ports.append({

                "port": port_number,

                "protocol": protocol,

                "state": state,

                "service": service,

                "risk": risk,

                "risk_reason": risk_reason

            })

        # ====================================================
        # RETURN RESULTS
        # ====================================================

        return (
            ports,
            None,
            scan_duration
        )

    # ========================================================
    # TIMEOUT
    # ========================================================

    except subprocess.TimeoutExpired:

        return (
            None,
            "Nmap scan timed out.",
            0
        )

    # ========================================================
    # NMAP NOT FOUND
    # ========================================================

    except FileNotFoundError:

        return (
            None,
            "Nmap was not found. Make sure Nmap is installed.",
            0
        )

    # ========================================================
    # OTHER ERROR
    # ========================================================

    except Exception as e:

        return (
            None,
            str(e),
            0
        )


# ============================================================
# SECURITY SUMMARY
# ============================================================

def build_security_summary(ports):

    high = 0
    medium = 0
    low = 0
    info = 0

    recommendations = []


    for port in ports:

        risk = port.get("risk", "LOW")


        if risk == "HIGH":

            high += 1


        elif risk == "MEDIUM":

            medium += 1


        elif risk == "INFO":

            info += 1


        else:

            low += 1


        # ====================================================
        # RECOMMENDATIONS
        # ====================================================

        if risk in ["HIGH", "MEDIUM"]:

            recommendations.append({

                "port": port.get("port"),

                "risk": risk,

                "message": port.get(
                    "risk_reason",
                    "Review this exposed service."
                )

            })


    # ========================================================
    # OVERALL RISK
    # ========================================================

    if high > 0:

        risk_level = "HIGH"


    elif medium > 0:

        risk_level = "MEDIUM"


    else:

        risk_level = "LOW"


    return {

        "high": high,

        "medium": medium,

        "low": low,

        "info": info,

        "total_open_ports": len(ports),

        "risk_level": risk_level,

        "recommendations": recommendations

    }


# ============================================================
# SIGNUP
# ============================================================

@app.route("/signup", methods=["POST"])
def signup():

    try:

        data = request.get_json()


        if not data:

            return jsonify({
                "error": "Request body is required."
            }), 400


        username = str(
            data.get("username", "")
        ).strip()


        password = str(
            data.get("password", "")
        )


        # ====================================================
        # VALIDATION
        # ====================================================

        if not username:

            return jsonify({
                "error": "Username is required."
            }), 400


        if len(username) < 3:

            return jsonify({
                "error": "Username must be at least 3 characters."
            }), 400


        if len(password) < 6:

            return jsonify({
                "error": "Password must be at least 6 characters."
            }), 400


        # ====================================================
        # CHECK EXISTING USER
        # ====================================================

        existing = (
            supabase
            .table("users")
            .select("id, username")
            .eq("username", username)
            .execute()
        )


        if existing.data:

            return jsonify({
                "error": "Username already exists."
            }), 409


        # ====================================================
        # HASH PASSWORD
        # ====================================================

        password_hash = generate_password_hash(
            password
        )


        # ====================================================
        # CREATE USER
        # ====================================================

        result = (
            supabase
            .table("users")
            .insert({
                "username": username,
                "password_hash": password_hash
            })
            .execute()
        )


        if not result.data:

            return jsonify({
                "error": "Unable to create account."
            }), 500


        return jsonify({

            "success": True,

            "message": "Account created successfully.",

            "username": username

        }), 201


    except Exception as e:

        print("SIGNUP ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["POST"])
def login():

    try:

        data = request.get_json()


        if not data:

            return jsonify({
                "error": "Request body is required."
            }), 400


        username = str(
            data.get("username", "")
        ).strip()


        password = str(
            data.get("password", "")
        )


        # ====================================================
        # VALIDATION
        # ====================================================

        if not username or not password:

            return jsonify({
                "error": "Username and password are required."
            }), 400


        # ====================================================
        # FIND USER
        # ====================================================

        result = (
            supabase
            .table("users")
            .select("id, username, password_hash")
            .eq("username", username)
            .limit(1)
            .execute()
        )


        if not result.data:

            return jsonify({
                "error": "Invalid username or password."
            }), 401


        user = result.data[0]


        # ====================================================
        # CHECK PASSWORD
        # ====================================================

        password_valid = check_password_hash(
            user["password_hash"],
            password
        )


        if not password_valid:

            return jsonify({
                "error": "Invalid username or password."
            }), 401


        # ====================================================
        # SUCCESS
        # ====================================================

        return jsonify({

            "success": True,

            "message": "Login successful.",

            "username": user["username"],

            "user_id": user["id"]

        }), 200


    except Exception as e:

        print("LOGIN ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({

        "message": "Port Scanner Backend is running!"

    })


# ============================================================
# SEND EMAIL REPORT
# ============================================================

def send_email_report(
    recipient_email,
    target,
    scan_type,
    scan_duration,
    ports,
    security
):

    try:

        # ====================================================
        # CREATE EMAIL
        # ====================================================

        message = EmailMessage()

        message["Subject"] = (
            f"Security Scan Report - {target}"
        )

        message["From"] = EMAIL_ADDRESS

        message["To"] = recipient_email

        # ====================================================
        # BUILD PORT TABLE
        # ====================================================

        if ports:

            port_rows = ""

            for port in ports:

                port_rows += f"""
                <tr>
                    <td>{port.get("port", "")}</td>
                    <td>{port.get("protocol", "")}</td>
                    <td>{port.get("state", "")}</td>
                    <td>{port.get("service", "")}</td>
                    <td>{port.get("risk", "")}</td>
                </tr>
                """

        else:

            port_rows = """
            <tr>
                <td colspan="5">
                    No open ports were detected.
                </td>
            </tr>
            """

        # ====================================================
        # BUILD RECOMMENDATIONS
        # ====================================================

        recommendations = security.get(
            "recommendations",
            []
        )

        if recommendations:

            recommendation_html = ""

            for recommendation in recommendations:

                recommendation_html += f"""
                <li>
                    <strong>
                        Port {recommendation.get("port", "")}
                    </strong>
                    -
                    {recommendation.get("message", "")}
                </li>
                """

        else:

            recommendation_html = """
            <li>
                No specific security recommendations.
            </li>
            """

        # ====================================================
        # EMAIL HTML
        # ====================================================

        html_body = f"""
        <!DOCTYPE html>

        <html>

        <head>

            <style>

                body {{
                    font-family: Arial, sans-serif;
                    background: #f4f6f8;
                    padding: 20px;
                }}

                .container {{
                    max-width: 900px;
                    margin: auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                }}

                h1 {{
                    margin-bottom: 5px;
                }}

                h2 {{
                    margin-top: 30px;
                }}

                .summary {{
                    display: grid;
                    grid-template-columns:
                        repeat(4, 1fr);
                    gap: 10px;
                    margin-top: 20px;
                }}

                .card {{
                    padding: 15px;
                    border-radius: 8px;
                    background: #f1f3f5;
                    text-align: center;
                }}

                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                }}

                th,
                td {{
                    border: 1px solid #ddd;
                    padding: 10px;
                    text-align: left;
                }}

                th {{
                    background: #f1f3f5;
                }}

                ul {{
                    line-height: 1.8;
                }}

                .footer {{
                    margin-top: 30px;
                    color: #777;
                    font-size: 13px;
                }}

            </style>

        </head>

        <body>

            <div class="container">

                <h1>
                    Security Scanner Report
                </h1>

                <p>
                    Nmap-based Network Security Assessment
                </p>

                <h2>
                    Scan Information
                </h2>

                <p>
                    <strong>Target:</strong>
                    {target}
                </p>

                <p>
                    <strong>Scan Type:</strong>
                    {scan_type}
                </p>

                <p>
                    <strong>Scan Duration:</strong>
                    {scan_duration} seconds
                </p>

                <p>
                    <strong>Overall Risk:</strong>
                    {security.get("risk_level", "LOW")}
                </p>

                <div class="summary">

                    <div class="card">
                        <strong>
                            {security.get("total_open_ports", 0)}
                        </strong>
                        <br>
                        Open Ports
                    </div>

                    <div class="card">
                        <strong>
                            {security.get("high", 0)}
                        </strong>
                        <br>
                        High Risk
                    </div>

                    <div class="card">
                        <strong>
                            {security.get("medium", 0)}
                        </strong>
                        <br>
                        Medium Risk
                    </div>

                    <div class="card">
                        <strong>
                            {security.get("low", 0)}
                        </strong>
                        <br>
                        Low Risk
                    </div>

                </div>

                <h2>
                    Open Ports
                </h2>

                <table>

                    <thead>

                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Risk</th>
                        </tr>

                    </thead>

                    <tbody>

                        {port_rows}

                    </tbody>

                </table>

                <h2>
                    Security Recommendations
                </h2>

                <ul>

                    {recommendation_html}

                </ul>

                <div class="footer">

                    Generated by Security Scanner

                    <br>

                    Nmap-based Network Security Assessment

                </div>

            </div>

        </body>

        </html>
        """

        # ====================================================
        # SET EMAIL CONTENT
        # ====================================================

        message.set_content(
            "Please view this email in an HTML-compatible email client."
        )

        message.add_alternative(
            html_body,
            subtype="html"
        )

        # ====================================================
        # CONNECT TO GMAIL SMTP
        # ====================================================

        with smtplib.SMTP(
            "smtp.gmail.com",
            587
        ) as server:

            server.starttls()

            server.login(
                EMAIL_ADDRESS,
                EMAIL_PASSWORD
            )

            server.send_message(message)

        return True, None

    except Exception as e:

        print(
            "EMAIL ERROR:",
            e
        )

        return False, str(e)


# ============================================================
# SEND EMAIL REPORT
# ============================================================

@app.route("/email-report", methods=["POST"])
def email_report():
    try:
        data = request.get_json()

        print("================================")
        print("EMAIL REPORT REQUEST RECEIVED")
        print("================================")
        print(data)

        if not data:
            return jsonify({
                "error": "Request body is required."
            }), 400

        # ====================================================
        # GET DATA FROM FRONTEND
        # ====================================================

        recipient_email = str(
            data.get("recipient", "")
        ).strip()

        target = str(
            data.get("target", "")
        ).strip()

        scan_type = str(
            data.get("scan_type", "Full TCP")
        )

        scan_duration = data.get(
            "scan_duration",
            0
        )

        ports = data.get(
            "ports",
            []
        )

        # ====================================================
        # BUILD SECURITY DATA
        # ====================================================

        risk_summary = data.get(
            "risk_summary",
            {}
        )

        security = {
            "high": risk_summary.get("high", 0),
            "medium": risk_summary.get("medium", 0),
            "low": risk_summary.get("low", 0),
            "info": risk_summary.get("info", 0),
            "total_open_ports": data.get(
                "total_open_ports",
                len(ports)
            ),
            "risk_level": data.get(
                "overall_risk",
                "LOW"
            ),
            "recommendations": []
        }

        # ====================================================
        # BUILD RECOMMENDATIONS
        # ====================================================

        recommendations = data.get(
            "recommendations",
            []
        )

        for recommendation in recommendations:

            # Frontend sends strings
            if isinstance(recommendation, str):

                security["recommendations"].append({
                    "port": "",
                    "risk": "",
                    "message": recommendation
                })

            # Also support object format
            elif isinstance(recommendation, dict):

                security["recommendations"].append({
                    "port": recommendation.get(
                        "port",
                        ""
                    ),
                    "risk": recommendation.get(
                        "risk",
                        ""
                    ),
                    "message": recommendation.get(
                        "message",
                        ""
                    )
                })

        # ====================================================
        # VALIDATION
        # ====================================================

        if not recipient_email:
            return jsonify({
                "error": "Email address is required."
            }), 400

        if "@" not in recipient_email:
            return jsonify({
                "error": "Please enter a valid email address."
            }), 400

        if not target:
            return jsonify({
                "error": "Target is required."
            }), 400

        if not EMAIL_ADDRESS:
            return jsonify({
                "error": "EMAIL_ADDRESS is not configured in .env"
            }), 500

        if not EMAIL_PASSWORD:
            return jsonify({
                "error": "EMAIL_PASSWORD is not configured in .env"
            }), 500

        # ====================================================
        # SEND EMAIL
        # ====================================================

        success, error = send_email_report(
            recipient_email=recipient_email,
            target=target,
            scan_type=scan_type,
            scan_duration=scan_duration,
            ports=ports,
            security=security
        )

        # ====================================================
        # EMAIL FAILED
        # ====================================================

        if not success:

            print(
                "EMAIL SEND FAILED:",
                error
            )

            return jsonify({
                "success": False,
                "error": error
            }), 500

        # ====================================================
        # EMAIL SUCCESS
        # ====================================================

        print(
            "EMAIL SENT SUCCESSFULLY TO:",
            recipient_email
        )

        return jsonify({
            "success": True,
            "message":
                "Security scan report sent successfully.",
            "email":
                recipient_email
        }), 200

    except Exception as e:

        print(
            "EMAIL REPORT ERROR:",
            e
        )

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
        

# ============================================================
# SCAN
# ============================================================

@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.get_json()


        if not data:

            return jsonify({
                "error": "Request body is required."
            }), 400


        target = data.get("target")
        user_id = data.get("user_id")


        scan_type = data.get(
            "scan_type",
            "Full TCP"
        )

        timing = data.get(
            "timing",
            "T3"
        )

        custom_ports = data.get(
            "custom_ports", 
            ""
        )

        print(
            "DEBUG custom_ports:",
            repr(custom_ports),
            "TYPE:",
            type(custom_ports)
        )

        allowed_scan_types = [
            "Quick TCP",
            "Full TCP",
            "UDP",
            "Aggressive",
            "Custom Ports",
            "Verbosity Scan"
        ]

        # ====================================================
        # VALIDATE TIMING
        # ====================================================

        allowed_timings = [
            "T0",
            "T1",
            "T2",
            "T3",
            "T4",
            "T5"
        ]

        if timing not in allowed_timings:
            return jsonify({
                "error": "Invalid timing. Choose T0, T1, T2, T3, T4 or T5."
            }), 400


        # ====================================================
        # VALIDATE TARGET
        # ====================================================

        if not target:

            return jsonify({
                "error": "Target is required."
            }), 400

        if not user_id:

            return jsonify({
                "error": "User ID is required."
            }), 401

        target = str(target).strip()


        # ====================================================
        # VALIDATE SCAN TYPE
        # ====================================================

        if scan_type not in allowed_scan_types:
            return jsonify({
                "error": (
                    "Invalid scan type. Choose Quick TCP, Full TCP, "
                    "UDP, Aggressive, Custom Ports or Verbosity Scan."
                )
            }), 400


        # ====================================================
        # RUN NMAP
        # ====================================================

        ports, error, scan_duration = parse_nmap_output(
            target,
            scan_type,
            custom_ports,
            timing
        )


        # ====================================================
        # NMAP ERROR
        # ====================================================

        if error:

            return jsonify({
                "error": error
            }), 500


        # ====================================================
        # SECURITY ANALYSIS
        # ====================================================

        security = build_security_summary(
            ports
        )


        # ====================================================
        # SAVE TO SUPABASE
        # ====================================================

        save_scan_history(

            user_id=user_id,

            target=target,

            scan_type=scan_type,

            scan_duration=scan_duration,

            ports=ports,

            security=security

        )


        # ====================================================
        # RETURN RESULT
        # ====================================================

        return jsonify({

            "success": True,

            "target": target,

            "scan_type": scan_type,

            "timing": timing,

            "scan_duration": scan_duration,

            "ports": ports,

            "security": security

        }), 200


    except Exception as e:

        print("SCAN ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500
    

# ============================================================
# VERBOSITY SCAN
# ============================================================

@app.route("/verbosity-scan", methods=["POST"])
def verbosity_scan():
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "error": "Request body is required."
            }), 400

        target = str(data.get("target", "")).strip()
        timing = str(data.get("timing", "T3")).upper().strip()

        # ----------------------------------------------------
        # VALIDATE TARGET
        # ----------------------------------------------------

        if not target:
            return jsonify({
                "error": "Target is required."
            }), 400

        # ----------------------------------------------------
        # VALIDATE TIMING
        # ----------------------------------------------------

        allowed_timings = [
            "T0",
            "T1",
            "T2",
            "T3",
            "T4",
            "T5"
        ]

        if timing not in allowed_timings:
            return jsonify({
                "error": "Invalid timing. Choose T0, T1, T2, T3, T4 or T5."
            }), 400

        # ----------------------------------------------------
        # RUN NMAP
        # ----------------------------------------------------

        nmap_args = [
            NMAP_PATH,
            f"-{timing}",
            "--open",
            "-sV",
            target
        ]

        print("================================")
        print("VERBOSITY SCAN")
        print("================================")
        print("Target:", target)
        print("Timing:", timing)
        print("Command:", nmap_args)

        scan_start = time.perf_counter()

        result = subprocess.run(
            nmap_args,
            capture_output=True,
            text=True,
            timeout=600
        )

        scan_duration = round(
            time.perf_counter() - scan_start,
            2
        )

        # ----------------------------------------------------
        # NMAP ERROR
        # ----------------------------------------------------

        if result.returncode != 0:
            error_message = result.stderr.strip()

            if not error_message:
                error_message = result.stdout.strip()

            return jsonify({
                "error": error_message
            }), 500

        # ----------------------------------------------------
        # PARSE OPEN PORTS
        # ----------------------------------------------------

        ports = []

        for line in result.stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            match = re.match(
                r"^(\d+)\/(tcp|udp)\s+(\w+)\s+(.+)$",
                line,
                re.IGNORECASE
            )

            if not match:
                continue

            port, protocol, state, service = match.groups()

            port_number = int(port)
            protocol = protocol.lower()
            state = state.lower()
            service = service.strip()

            if state != "open":
                continue

            risk, risk_reason = analyze_port(
                port_number,
                service,
                protocol
            )

            ports.append({
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "service": service,
                "risk": risk,
                "risk_reason": risk_reason
            })

        # ----------------------------------------------------
        # SECURITY SUMMARY
        # ----------------------------------------------------

        security = build_security_summary(ports)

        # ----------------------------------------------------
        # RETURN RESULT
        # ----------------------------------------------------

        return jsonify({
            "success": True,
            "target": target,
            "timing": timing,
            "scan_duration": scan_duration,
            "ports": ports,
            "security": security
        }), 200

    except subprocess.TimeoutExpired:
        return jsonify({
            "error": "Nmap timing scan timed out."
        }), 500

    except Exception as e:
        print("VERBOSITY SCAN ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500

# ============================================================
# SAVE SCAN HISTORY
# ============================================================

def save_scan_history(
    user_id,
    target,
    scan_type,
    scan_duration,
    ports,
    security
):

    try:

        # ====================================================
        # CURRENT UTC TIME
        # ====================================================

        scan_date = datetime.now(
            timezone.utc
        ).isoformat()

        # ====================================================
        # FIND EXISTING TARGET
        # ====================================================

        existing_target = (
            supabase
            .table("targets")
            .select(
                "id, target, scan_count"
            )
            .eq(
                "target",
                target
            )
            .limit(1)
            .execute()
        )

        # ====================================================
        # TARGET ALREADY EXISTS
        # ====================================================

        if existing_target.data:

            target_record = existing_target.data[0]

            target_id = target_record["id"]

            current_count = (
                target_record.get(
                    "scan_count",
                    0
                ) or 0
            )

            new_count = current_count + 1

            (
                supabase
                .table("targets")
                .update({
                    "last_scan_at": scan_date,
                    "scan_count": new_count
                })
                .eq(
                    "id",
                    target_id
                )
                .execute()
            )

        # ====================================================
        # NEW TARGET
        # ====================================================

        else:

            new_target = (
                supabase
                .table("targets")
                .insert({
                    "target": target,
                    "created_at": scan_date,
                    "last_scan_at": scan_date,
                    "scan_count": 1
                })
                .execute()
            )

            if not new_target.data:

                raise Exception(
                    "Unable to create target record."
                )

            target_id = new_target.data[0]["id"]

        # ====================================================
        # CREATE SCAN HISTORY RECORD
        # ====================================================

        history_record = {

            "user_id": user_id,

            "target_id": target_id,

            "target": target,

            "scan_type": scan_type,

            "scan_duration": scan_duration,

            "scan_date": scan_date,

            "ports": ports,

            "high_risk": security["high"],

            "medium_risk": security["medium"],

            "low_risk": security["low"],

            "info_risk": security["info"],

            "total_open_ports":
                security["total_open_ports"],

            "risk_level":
                security["risk_level"],

            "recommendations":
                security["recommendations"]

        }

        # ====================================================
        # SAVE HISTORY
        # ====================================================

        result = (
            supabase
            .table("scan_history")
            .insert(history_record)
            .execute()
        )

        return result

    except Exception as e:

        print(
            "SAVE SCAN HISTORY ERROR:",
            e
        )

        raise


# ============================================================
# GET SCAN HISTORY
# ============================================================

@app.route("/history", methods=["GET"])
def get_history():
    try:
        user_id = request.args.get("user_id")

        if not user_id:
            return jsonify({
                "error": "User ID is required."
            }), 400

        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return jsonify({
                "error": "Invalid user ID."
            }), 400

        result = (
            supabase
            .table("scan_history")
            .select("*")
            .eq("user_id", user_id)
            .order("id", desc=True)
            .execute()
        )

        history = result.data or []

        return jsonify({
            "success": True,
            "history": history
        }), 200

    except Exception as e:
        print("HISTORY ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500

# ============================================================
# DELETE ONE HISTORY RECORD
# ============================================================

@app.route(
    "/history/<int:scan_id>",
    methods=["DELETE"]
)
def delete_history(scan_id):

    try:

        result = (
            supabase
            .table("scan_history")
            .delete()
            .eq("id", scan_id)
            .execute()
        )


        if not result.data:

            return jsonify({

                "error":
                    "Scan history record not found."

            }), 404


        return jsonify({

            "success": True,

            "message":
                "Scan history deleted successfully."

        }), 200


    except Exception as e:

        print("DELETE HISTORY ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# DELETE ALL HISTORY
# ============================================================

@app.route(
    "/history",
    methods=["DELETE"]
)
def clear_history():

    try:

        # Delete all records
        result = (
            supabase
            .table("scan_history")
            .delete()
            .neq("id", 0)
            .execute()
        )


        return jsonify({

            "success": True,

            "message":
                "All scan history cleared successfully."

        }), 200


    except Exception as e:

        print("CLEAR HISTORY ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health",
    methods=["GET"]
)
def health():

    return jsonify({

        "status": "ok",

        "service": "Port Scanner Backend"

    }), 200


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )