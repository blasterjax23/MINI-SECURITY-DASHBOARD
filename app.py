import os
import sqlite3
import ipaddress
import datetime
import csv
from io import StringIO
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Constants
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security.db")

# Helper function to get database connection
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Database Initialization
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP DEFAULT NULL
        )
    """)
    
    # Whitelist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Blacklist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Login Log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            ip_address TEXT,
            event_type TEXT,
            ip_classification TEXT
        )
    """)
    
    conn.commit()
    conn.close()

def normalize_ip(ip_str):
    ip_str = ip_str.strip()
    # Handle IPv4 leading zeros (e.g., 10.100.09.01 -> 10.100.9.1)
    if "." in ip_str and ":" not in ip_str:
        parts = ip_str.split(".")
        if len(parts) == 4:
            normalized_parts = []
            for part in parts:
                if part.isdigit():
                    normalized_parts.append(str(int(part)))
                else:
                    normalized_parts.append(part)
            return ".".join(normalized_parts)
    return ip_str

# IP Classification Engine
def classify_ip(ip_str):
    ip_str = normalize_ip(ip_str)
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Invalid"
        
    # 1. Loopback (127.0.0.0/8, ::1)
    if ip.is_loopback:
        return "Loopback"
        
    # 2. Private (RFC 1918)
    private_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16")
    ]
    for net in private_networks:
        if ip in net:
            return "Private"
            
    # 3. Military (DoD ranges)
    military_networks = [
        ipaddress.ip_network("6.0.0.0/8"),
        ipaddress.ip_network("11.0.0.0/8"),
        ipaddress.ip_network("21.0.0.0/8"),
        ipaddress.ip_network("22.0.0.0/8"),
        ipaddress.ip_network("26.0.0.0/8"),
        ipaddress.ip_network("28.0.0.0/8"),
        ipaddress.ip_network("29.0.0.0/8"),
        ipaddress.ip_network("30.0.0.0/8"),
        ipaddress.ip_network("33.0.0.0/8"),
        ipaddress.ip_network("55.0.0.0/8"),
        ipaddress.ip_network("214.0.0.0/8"),
        ipaddress.ip_network("215.0.0.0/8")
    ]
    for net in military_networks:
        if ip in net:
            return "Military"
            
    # 4. Reserved/R&D (IANA reserved blocks)
    reserved_networks = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("255.255.255.255/32")
    ]
    for net in reserved_networks:
        if ip in net:
            return "Reserved/R&D"
            
    if ip.version == 6:
        if ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return "Reserved/R&D"
            
    return "Public"

# Helper to get the request client IP (supporting simulation panel)
def get_client_ip():
    # Frontend can pass simulated client IP in custom header X-Simulated-IP
    simulated_ip = request.headers.get("X-Simulated-IP")
    if simulated_ip:
        return simulated_ip.strip()
    
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.remote_addr

# Password Strength Validator (Backend backup)
def validate_password_strength(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    special_chars = "!@#$%^&*(),.?\":{}|<>"
    if not any(c in special_chars for c in password):
        return False
    return True

# ----------------- ROUTES -----------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats", methods=["GET"])
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 4 grid cards
    cursor.execute("SELECT COUNT(*) FROM users")
    accounts_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM whitelist")
    whitelist_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM blacklist")
    blacklist_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM login_log")
    login_events_count = cursor.fetchone()[0]
    
    # Threat summary details
    cursor.execute("SELECT COUNT(*) FROM login_log WHERE event_type = 'success'")
    success_logins = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM login_log WHERE event_type = 'failed'")
    failed_logins = cursor.fetchone()[0]
    
    # Suspicious IPs (3+ failed attempts)
    cursor.execute("""
        SELECT ip_address, COUNT(*) as fail_count 
        FROM login_log 
        WHERE event_type = 'failed' 
        GROUP BY ip_address 
        HAVING fail_count >= 3
    """)
    suspicious_ips = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({
        "accounts_count": accounts_count,
        "whitelist_count": whitelist_count,
        "blacklist_count": blacklist_count,
        "login_events_count": login_events_count,
        "success_logins": success_logins,
        "failed_logins": failed_logins,
        "suspicious_ips": suspicious_ips
    })

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    ip_address = data.get("ip_address", "").strip()
    
    if not username or not password or not ip_address:
        return jsonify({"status": "error", "message": "Username, password, and IP address are required."}), 400
        
    ip_class = classify_ip(ip_address)
    
    if ip_class == "Invalid":
        return jsonify({
            "status": "error",
            "message": "Account creation blocked: Invalid IP address format.",
            "ip_type": "Invalid"
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check failed login attempts from this IP address
    cursor.execute("""
        SELECT COUNT(*) FROM login_log 
        WHERE ip_address = ? AND event_type = 'failed'
    """, (ip_address,))
    failed_count = cursor.fetchone()[0]
    
    if failed_count > 3:
        # Log signup_blocked
        cursor.execute("""
            INSERT INTO login_log (username, ip_address, event_type, ip_classification)
            VALUES (?, ?, 'signup_blocked', ?)
        """, (username, ip_address, f"Suspicious IP ({failed_count} fails)"))
        conn.commit()
        conn.close()
        return jsonify({
            "status": "error",
            "message": f"Account creation blocked: IP address {ip_address} has more than 3 failed login attempts ({failed_count}).",
            "ip_type": ip_class
        }), 403

    # Check if username already exists
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"status": "error", "message": "Username is already taken."}), 400
        
    # Create the user
    password_hash = generate_password_hash(password)
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """, (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "Failed to create user account."}), 500
        
    conn.close()
    return jsonify({
        "status": "success",
        "message": "Account created successfully!",
        "ip_type": ip_class
    })

@app.route("/api/login", methods=["POST"])
def login_route():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required."}), 400
        
    client_ip = get_client_ip()
    ip_class = classify_ip(client_ip)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if IP is blacklisted
    cursor.execute("SELECT 1 FROM blacklist WHERE ip_address = ?", (client_ip,))
    if cursor.fetchone():
        cursor.execute("""
            INSERT INTO login_log (username, ip_address, event_type, ip_classification)
            VALUES (?, ?, 'failed', ?)
        """, (username, client_ip, f"Blacklisted ({ip_class})"))
        conn.commit()
        conn.close()
        return jsonify({
            "status": "error",
            "message": "Login blocked: This IP address is blacklisted.",
            "ip_type": ip_class
        }), 403
        
    # Get user
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        # User not found -> log failed attempt
        cursor.execute("""
            INSERT INTO login_log (username, ip_address, event_type, ip_classification)
            VALUES (?, ?, 'failed', ?)
        """, (username, client_ip, ip_class))
        conn.commit()
        conn.close()
        return jsonify({"status": "error", "message": "Invalid username or password."}), 401
        
    # Check lock status
    if user["locked_until"]:
        locked_until_dt = datetime.datetime.fromisoformat(user["locked_until"])
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if now_utc < locked_until_dt:
            remaining_seconds = int((locked_until_dt - now_utc).total_seconds())
            conn.close()
            return jsonify({
                "status": "error",
                "message": f"Account is locked due to security policy. Try again in {remaining_seconds} seconds.",
                "remaining_attempts": 0
            }), 403
        else:
            # Lock has expired, reset failed attempts
            cursor.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
            conn.commit()
            
    # Verify password
    if check_password_hash(user["password_hash"], password):
        # Reset failed attempts and locked status
        cursor.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        
        # Log success
        cursor.execute("""
            INSERT INTO login_log (username, ip_address, event_type, ip_classification)
            VALUES (?, ?, 'success', ?)
        """, (username, client_ip, ip_class))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        # Increment failed attempts
        failed_attempts = user["failed_attempts"] + 1
        locked_until = None
        message = "Invalid username or password."
        
        if failed_attempts >= 3:
            now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            lockout_time = now_utc + datetime.timedelta(minutes=15)
            locked_until = lockout_time.isoformat()
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = ?, locked_until = ? 
                WHERE id = ?
            """, (failed_attempts, locked_until, user["id"]))
            message = "Invalid username or password. Account has been locked for 15 minutes."
        else:
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = ? 
                WHERE id = ?
            """, (failed_attempts, user["id"]))
            
        # Log failure
        cursor.execute("""
            INSERT INTO login_log (username, ip_address, event_type, ip_classification)
            VALUES (?, ?, 'failed', ?)
        """, (username, client_ip, ip_class))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "error",
            "message": message,
            "remaining_attempts": max(0, 3 - failed_attempts)
        }), 401

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")
    
    if not username or not new_password or not confirm_password:
        return jsonify({"status": "error", "message": "All fields are required."}), 400
        
    if new_password != confirm_password:
        return jsonify({"status": "error", "message": "Passwords do not match."}), 400
        
    if not validate_password_strength(new_password):
        return jsonify({"status": "error", "message": "New password does not meet strength requirements."}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({"status": "error", "message": "User does not exist."}), 404
        
    # Check if currently locked
    if user["locked_until"]:
        locked_until_dt = datetime.datetime.fromisoformat(user["locked_until"])
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if now_utc < locked_until_dt:
            conn.close()
            return jsonify({"status": "error", "message": "Account is locked. Cannot reset password at this time."}), 403
            
    password_hash = generate_password_hash(new_password)
    cursor.execute("""
        UPDATE users 
        SET password_hash = ?, failed_attempts = 0, locked_until = NULL 
        WHERE id = ?
    """, (password_hash, user["id"]))
    
    conn.commit()
    conn.close()
    
    return jsonify({"status": "success", "message": "Password reset successfully!"})

@app.route("/api/ip-manager", methods=["GET"])
def ip_manager():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, ip_address, created_at FROM whitelist ORDER BY created_at DESC")
    whitelist = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute("SELECT id, ip_address, created_at FROM blacklist ORDER BY created_at DESC")
    blacklist = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({
        "whitelist": whitelist,
        "blacklist": blacklist
    })

@app.route("/api/ip-manager/add", methods=["POST"])
def ip_manager_add():
    data = request.get_json() or {}
    ip_address = data.get("ip_address", "").strip()
    list_type = data.get("list_type", "").strip() # 'whitelist' or 'blacklist'
    
    if not ip_address or list_type not in ["whitelist", "blacklist"]:
        return jsonify({"status": "error", "message": "Invalid parameters."}), 400
        
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid IP address format."}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if list_type == "whitelist":
        # Remove from blacklist if present
        cursor.execute("DELETE FROM blacklist WHERE ip_address = ?", (ip_address,))
        try:
            cursor.execute("INSERT INTO whitelist (ip_address) VALUES (?)", (ip_address,))
            conn.commit()
        except sqlite3.IntegrityError:
            pass # Already exists in whitelist
    else:
        # Remove from whitelist if present
        cursor.execute("DELETE FROM whitelist WHERE ip_address = ?", (ip_address,))
        try:
            cursor.execute("INSERT INTO blacklist (ip_address) VALUES (?)", (ip_address,))
            conn.commit()
        except sqlite3.IntegrityError:
            pass # Already exists in blacklist
            
    conn.close()
    return jsonify({"status": "success", "message": f"IP added to {list_type} successfully!"})

@app.route("/api/ip-manager/remove", methods=["POST"])
def ip_manager_remove():
    data = request.get_json() or {}
    ip_address = data.get("ip_address", "").strip()
    list_type = data.get("list_type", "").strip() # 'whitelist' or 'blacklist'
    
    if not ip_address or list_type not in ["whitelist", "blacklist"]:
        return jsonify({"status": "error", "message": "Invalid parameters."}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if list_type == "whitelist":
        cursor.execute("DELETE FROM whitelist WHERE ip_address = ?", (ip_address,))
    else:
        cursor.execute("DELETE FROM blacklist WHERE ip_address = ?", (ip_address,))
        
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": f"IP removed from {list_type}."})

@app.route("/api/ip-manager/lookup", methods=["POST"])
def ip_manager_lookup():
    data = request.get_json() or {}
    ip_address = data.get("ip_address", "").strip()
    
    if not ip_address:
        return jsonify({"status": "error", "message": "IP address is required."}), 400
        
    ip_class = classify_ip(ip_address)
    if ip_class == "Invalid":
        return jsonify({"status": "error", "message": "Invalid IP address format."}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM whitelist WHERE ip_address = ?", (ip_address,))
    is_whitelisted = cursor.fetchone() is not None
    
    cursor.execute("SELECT 1 FROM blacklist WHERE ip_address = ?", (ip_address,))
    is_blacklisted = cursor.fetchone() is not None
    
    conn.close()
    
    status = "Standard"
    if is_whitelisted:
        status = "Whitelisted"
    elif is_blacklisted:
        status = "Blacklisted"
        
    return jsonify({
        "status": "success",
        "ip_address": ip_address,
        "classification": ip_class,
        "list_status": status
    })

@app.route("/api/logs", methods=["GET"])
def get_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT timestamp, username, ip_address, event_type, ip_classification 
        FROM login_log 
        ORDER BY timestamp DESC
    """)
    logs = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return jsonify({
        "logs": logs
    })

@app.route("/api/logs/csv", methods=["GET"])
def export_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT timestamp, username, ip_address, event_type, ip_classification FROM login_log ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Timestamp", "Username", "IP Address", "Event Type", "IP Classification"])
    
    for row in rows:
        cw.writerow([row["timestamp"], row["username"], row["ip_address"], row["event_type"], row["ip_classification"]])
        
    output = si.getvalue()
    
    return send_file(
        StringIO(output),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"security_logs_{datetime.date.today()}.csv"
    )

if __name__ == "__main__":
    init_db()
    # Host 127.0.0.1 for local, port 5000
    app.run(debug=True, host="127.0.0.1", port=5000)
