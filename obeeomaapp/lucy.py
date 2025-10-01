import os
import psycopg2
from dotenv import load_dotenv

# Load .env file
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT version();")
    db_version = cur.fetchone()
    print("✅ Successfully connected! PostgreSQL version:", db_version)
    cur.close()
    conn.close()
except Exception as e:
    print("❌ Connection failed:", e)
