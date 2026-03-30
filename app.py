from flask import Flask, request, jsonify
import os
import psycopg2
import bcrypt
import jwt
import datetime
from flask_cors import CORS
from functools import wraps


app = Flask(__name__)
CORS(app)
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback_secret")


@app.route("/create_tables", methods=["GET"])
def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        phone VARCHAR(20) UNIQUE,
        password VARCHAR(255),
        role VARCHAR(20)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        amount NUMERIC,
        currency_from VARCHAR(10),
        currency_to VARCHAR(10),
        rate NUMERIC,
        type VARCHAR(10),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    cur.close()
    conn.close()

    return "Tables created successfully!"


# --- توکن_required باید اول باشد ---
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
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- اتصال به دیتابیس ---
def get_connection():
    return psycopg2.connect(
        host="localhost",
        database="exchange_app",
        user="exchange_user",
        password="password123"
    )

# --- ثبت نام ---
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    name = data.get("name")
    phone = data.get("phone")
    password = data.get("password")
    role = data.get("role")
    if not all([name, phone, password, role]):
        return jsonify({"error": "All fields are required"}), 400
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, phone, password, role) VALUES (%s, %s, %s, %s)",
                    (name, phone, hashed.decode("utf-8"), role))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- ورود ---
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    phone = data.get("phone")
    password = data.get("password")
    if not all([phone, password]):
        return jsonify({"error": "Phone and password required"}), 400
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password, role FROM users WHERE phone=%s", (phone,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user:
            user_id, hashed_password, role = user
            if bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
                token = jwt.encode(
                    {"user_id": user_id, "role": role, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)},
                    SECRET_KEY,
                    algorithm="HS256"
                )
                return jsonify({"token": token}), 200
        return jsonify({"error": "Invalid phone or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- افزودن تراکنش ---
@app.route("/transaction", methods=["POST"])
@token_required
def add_transaction(current_user):
    if current_user["role"] != "saraf":
        return jsonify({"error": "Access denied"}), 403
    data = request.json
    user_id = data.get("user_id")
    amount = data.get("amount")
    currency_from = data.get("currency_from")
    currency_to = data.get("currency_to")
    rate = data.get("rate")
    type_ = data.get("type")
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO transactions (user_id, amount, currency_from, currency_to, rate, type) VALUES (%s,%s,%s,%s,%s,%s)",
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

from db_config import get_connection

# --- تست سرور در مرورگر ---
@app.route("/test", methods=["GET"])
def test_route():
    return "Server is running!"

@app.route("/", methods=["GET"])
def home():
    return "Exchange Backend is live!"

# --- اجرای سرور ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)