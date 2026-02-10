import sqlite3
import time
from flask import request, session

def log_action(user_id, role, action, resource, status, details=None):
    """
    Records an entry in the audit_logs table.
    """
    ip_address = request.remote_addr
    timestamp = int(time.time())
    
    try:
        conn = sqlite3.connect("database.db", timeout=5)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_logs (user_id, role, action, resource, status, timestamp, ip_address, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, role, action, resource, status, timestamp, ip_address, details))
        finally:
            conn.close()
    except Exception as e:
        print(f"Error logging audit trail: {e}")
