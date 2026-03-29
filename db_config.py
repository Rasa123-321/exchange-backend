import psycopg2

# تنظیمات دیتابیس
DB_NAME = "exchange_app"
DB_USER = "exchange_user"
DB_PASSWORD = "password123"
DB_HOST = "localhost"
DB_PORT = "5432"

def get_connection():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    return conn