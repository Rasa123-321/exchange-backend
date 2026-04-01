from flask import Flask, request, jsonify
from dotenv import load_dotenv
load_dotenv()
import os
import bcrypt
import jwt
import datetime
import pyotp
import base64
from io import BytesIO
import qrcode
from flask_cors import CORS
from functools import wraps
from db_config import get_connection

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is required in environment variables")


# -----------------------
# Helpers
# -----------------------
def generate_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token is missing"}), 401

        if token.startswith("Bearer "):
            token = token.split(" ")[1]

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


def make_qr_base64(data: str) -> str:
    img = qrcode.make(data)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("utf-8")


# -----------------------
# Create / update tables
# -----------------------
@app.route("/create_tables", methods=["GET"])
def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'customer',
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        is_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        two_fa_secret VARCHAR(255),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        amount NUMERIC NOT NULL,
        currency_from VARCHAR(10) NOT NULL,
        currency_to VARCHAR(10) NOT NULL,
        rate NUMERIC NOT NULL,
        type VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_transaction_user
            FOREIGN KEY (user_id) REFERENCES users(id)
            ON DELETE CASCADE
    );
    """)

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"message": "Tables created successfully"}), 200


# -----------------------
# Auth
# -----------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not all([name, phone, password]):
        return jsonify({"error": "name, phone, password are required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        conn = get_connection()
        cur = conn.cursor()

        # role از کاربر گرفته نمی‌شود
        cur.execute(
            """
            INSERT INTO users (name, phone, password, role)
            VALUES (%s, %s, %s, %s)
            RETURNING id, name, phone, role
            """,
            (name, phone, hashed, "customer")
        )
        user = cur.fetchone()
        conn.commit()

        cur.close()
        conn.close()

        return jsonify({
            "message": "User registered successfully",
            "user": {
                "id": user[0],
                "name": user[1],
                "phone": user[2],
                "role": user[3]
            }
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""
    otp_code = (data.get("otp_code") or "").strip()

    if not all([phone, password]):
        return jsonify({"error": "phone and password are required"}), 400

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, password, role, status, is_2fa_enabled, two_fa_secret
            FROM users
            WHERE phone = %s
        """, (phone,))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if not user:
            return jsonify({"error": "Invalid phone or password"}), 401

        user_id, hashed_password, role, status, is_2fa_enabled, two_fa_secret = user

        if status != "active":
            return jsonify({"error": "User account is not active"}), 403

        if not bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
            return jsonify({"error": "Invalid phone or password"}), 401

        if is_2fa_enabled:
            if not otp_code:
                return jsonify({
                    "error": "2FA code required",
                    "requires_2fa": True
                }), 401

            totp = pyotp.TOTP(two_fa_secret)
            if not totp.verify(otp_code, valid_window=1):
                return jsonify({"error": "Invalid 2FA code"}), 401

        token = generate_token(user_id, role)

        return jsonify({
            "message": "Login successful",
            "token": token,
            "requires_2fa": False
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# 2FA
# -----------------------
@app.route("/2fa/setup", methods=["POST"])
@token_required
def setup_2fa(current_user):
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT id, phone, is_2fa_enabled
            FROM users
            WHERE id = %s
        """, (current_user["user_id"],))
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        user_id, phone, is_2fa_enabled = user

        # اگر فعال است، دوباره secret جدید نسازیم
        if is_2fa_enabled:
            cur.close()
            conn.close()
            return jsonify({"error": "2FA is already enabled"}), 400

        secret = pyotp.random_base32()
        app_name = "AfghanExchange"
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=phone,
            issuer_name=app_name
        )

        qr_base64 = make_qr_base64(provisioning_uri)

        cur.execute("""
            UPDATE users
            SET two_fa_secret = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (secret, user_id))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "message": "2FA setup created",
            "secret": secret,
            "otpauth_url": provisioning_uri,
            "qr_code_base64": qr_base64
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/2fa/enable", methods=["POST"])
@token_required
def enable_2fa(current_user):
    data = request.json or {}
    otp_code = (data.get("otp_code") or "").strip()

    if not otp_code:
        return jsonify({"error": "otp_code is required"}), 400

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT two_fa_secret, is_2fa_enabled
            FROM users
            WHERE id = %s
        """, (current_user["user_id"],))
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        two_fa_secret, is_2fa_enabled = user

        if is_2fa_enabled:
            cur.close()
            conn.close()
            return jsonify({"error": "2FA already enabled"}), 400

        if not two_fa_secret:
            cur.close()
            conn.close()
            return jsonify({"error": "2FA setup not found. Call /2fa/setup first"}), 400

        totp = pyotp.TOTP(two_fa_secret)
        if not totp.verify(otp_code, valid_window=1):
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid 2FA code"}), 400

        cur.execute("""
            UPDATE users
            SET is_2fa_enabled = TRUE,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (current_user["user_id"],))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "2FA enabled successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/2fa/disable", methods=["POST"])
@token_required
def disable_2fa(current_user):
    data = request.json or {}
    password = data.get("password") or ""
    otp_code = (data.get("otp_code") or "").strip()

    if not password or not otp_code:
        return jsonify({"error": "password and otp_code are required"}), 400

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT password, two_fa_secret, is_2fa_enabled
            FROM users
            WHERE id = %s
        """, (current_user["user_id"],))
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        hashed_password, two_fa_secret, is_2fa_enabled = user

        if not is_2fa_enabled or not two_fa_secret:
            cur.close()
            conn.close()
            return jsonify({"error": "2FA is not enabled"}), 400

        if not bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid password"}), 401

        totp = pyotp.TOTP(two_fa_secret)
        if not totp.verify(otp_code, valid_window=1):
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid 2FA code"}), 400

        cur.execute("""
            UPDATE users
            SET is_2fa_enabled = FALSE,
                two_fa_secret = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (current_user["user_id"],))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "2FA disabled successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# Existing transaction routes
# فعلاً نگه می‌داریم، ولی بعداً باید با wallet/ledger بازنویسی شوند
# -----------------------
@app.route("/transaction", methods=["POST"])
@token_required
def add_transaction(current_user):
    if current_user["role"] != "saraf":
        return jsonify({"error": "Access denied"}), 403

    data = request.json or {}
    user_id = data.get("user_id")
    amount = data.get("amount")
    currency_from = data.get("currency_from")
    currency_to = data.get("currency_to")
    rate = data.get("rate")
    type_ = data.get("type")

    if not all([user_id, amount, currency_from, currency_to, rate, type_]):
        return jsonify({"error": "All transaction fields are required"}), 400

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        exists = cur.fetchone()
        if not exists:
            cur.close()
            conn.close()
            return jsonify({"error": "Target user not found"}), 404

        cur.execute(
            """
            INSERT INTO transactions (user_id, amount, currency_from, currency_to, rate, type)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (user_id, amount, currency_from, currency_to, rate, type_)
        )

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Transaction added"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/transactions", methods=["GET"])
@token_required
def get_transactions(current_user):
    try:
        conn = get_connection()
        cur = conn.cursor()

        if current_user["role"] == "saraf":
            cur.execute("SELECT * FROM transactions ORDER BY created_at DESC")
        else:
            cur.execute(
                "SELECT * FROM transactions WHERE user_id=%s ORDER BY created_at DESC",
                (current_user["user_id"],)
            )

        transactions = cur.fetchall()
        cur.close()
        conn.close()

        transactions_list = []
        for t in transactions:
            transactions_list.append({
                "id": t[0],
                "user_id": t[1],
                "amount": float(t[2]),
                "currency_from": t[3],
                "currency_to": t[4],
                "rate": float(t[5]),
                "type": t[6],
                "created_at": str(t[7])
            })

        return jsonify(transactions_list), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/test", methods=["GET"])
def test_route():
    return "Server is running!"


@app.route("/", methods=["GET"])
def home():
    return "Exchange Backend is live!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)