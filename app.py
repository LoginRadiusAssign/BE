from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import hashlib
import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"],  # Global rate limit
)

# Configuration
USER_FAILED_ATTEMPT_THRESHOLD = 5
USER_FAILED_ATTEMPT_WINDOW = 5  # minutes
USER_SUSPENSION_DURATION = 15  # minutes

IP_FAILED_ATTEMPT_THRESHOLD = 100
IP_FAILED_ATTEMPT_WINDOW = 5  # minutes

# ---------------- Database Helpers ----------------
def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        database=os.getenv('DB_NAME', 'login_db'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'postgres'),
        cursor_factory=RealDictCursor
    )
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

# ---------------- Utility Functions ----------------
def user_exists(email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists

def is_user_suspended(email):
    conn = get_db_connection()
    cur = conn.cursor()

    window_start = datetime.now() - timedelta(minutes=USER_FAILED_ATTEMPT_WINDOW)

    cur.execute("""
        SELECT COUNT(*) as attempt_count, MAX(attempted_at) as last_attempt
        FROM failed_login_attempts
        WHERE email = %s AND attempted_at > %s
    """, (email, window_start))

    result = cur.fetchone()
    cur.close()
    conn.close()

    if result['attempt_count'] >= USER_FAILED_ATTEMPT_THRESHOLD:
        last_attempt = result['last_attempt']
        suspension_end = last_attempt + timedelta(minutes=USER_SUSPENSION_DURATION)
        if datetime.now() < suspension_end:
            minutes_left = int((suspension_end - datetime.now()).total_seconds() / 60)
            return True, minutes_left

    return False, 0

def is_ip_blocked(ip_address):
    conn = get_db_connection()
    cur = conn.cursor()

    window_start = datetime.now() - timedelta(minutes=IP_FAILED_ATTEMPT_WINDOW)

    cur.execute("""
        SELECT COUNT(*) as attempt_count
        FROM failed_login_attempts
        WHERE ip_address = %s AND attempted_at > %s
    """, (ip_address, window_start))

    result = cur.fetchone()
    cur.close()
    conn.close()

    if result['attempt_count'] >= IP_FAILED_ATTEMPT_THRESHOLD:
        return True

    return False

def record_failed_attempt(email, ip_address):
    # Only record failed attempt if user actually exists
    if not user_exists(email):
        return

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO failed_login_attempts (email, ip_address, attempted_at)
        VALUES (%s, %s, %s)
    """, (email, ip_address, datetime.now()))

    conn.commit()
    cur.close()
    conn.close()

def clear_failed_attempts(email):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM failed_login_attempts WHERE email = %s", (email,))
    conn.commit()
    cur.close()
    conn.close()

def verify_user(email, password):
    conn = get_db_connection()
    cur = conn.cursor()

    hashed_password = hash_password(password)
    
    print(hashed_password,'---> ')

    cur.execute("""
        SELECT * FROM users
        WHERE email = %s AND password_hash = %s
    """, (email, hashed_password))

    user = cur.fetchone()
    cur.close()
    conn.close()

    return user is not None

# ---------------- Rate Limit Custom Handler ----------------
@app.errorhandler(429)
def ratelimit_error(e):
    return jsonify({
        'error': 'IP blocked due to too many requests. Please try again later.'
    }), 429

# ---------------- Routes ----------------
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute", key_func=get_remote_address)
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    ip_address = get_client_ip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Check if IP is blocked
    if is_ip_blocked(ip_address):
        return jsonify({'error': 'IP temporarily blocked due to excessive failed login attempts.'}), 403

    # Check if user is suspended
    suspended, minutes_left = is_user_suspended(email)
    if suspended:
        return jsonify({
            'error': f'Account temporarily suspended due to too many failed attempts. Try again in {minutes_left} minutes.'
        }), 403

    # Verify credentials
    if verify_user(email, password):
        clear_failed_attempts(email)
        return jsonify({'message': 'Login successful!', 'user': {'email': email}}), 200
    else:
        record_failed_attempt(email, ip_address)

        # Check if this attempt triggers suspension
        suspended, minutes_left = is_user_suspended(email)
        if suspended:
            return jsonify({'error': 'Account temporarily suspended due to too many failed attempts.'}), 403

        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200

# ---------------- Main ----------------
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
