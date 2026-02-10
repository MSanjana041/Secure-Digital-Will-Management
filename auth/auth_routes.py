from flask import Blueprint , request , redirect , render_template , session
import sqlite3 #SQLite database support
from auth.utils import generate_salt , hash_password,verify_password,generate_otp,otp_valid
import time
from will.crypto import generate_rsa_keys
from auth.audit import log_action
from auth.email_service import send_otp_email

#Blueprint - modularizes routes
#request - accesses form data sent by the browser(client)
#redirect - sends user to another URL(login page)
#render_template - renders HTML templates
#session - to remember user across requests , stored server side

# Flask registration

auth_bp = Blueprint("auth", __name__)
#creates an authentication blueprint

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]
        email = request.form["email"]

        salt = generate_salt()
        password_hash = hash_password(password, salt)

        if role == "Owner":
            private_key, public_key = generate_rsa_keys()
        else:
            private_key = None
            public_key = None

        conn = sqlite3.connect("database.db", timeout=5)
        try:
            with conn:
                cursor = conn.cursor()
                
                
                if role == "Executor":
                    cursor.execute("SELECT id FROM users WHERE role = 'Executor'")
                    if cursor.fetchone():
                        return render_template("alert.html", 
                                               type="error", 
                                               title="Executor Already Exists", 
                                               message="The system already has a designated executor. Only one executor is allowed for this secure digital will platform.",
                                               back_url="/register",
                                               back_label="Back to Register")
                
                cursor.execute(
                    """
                    INSERT INTO users 
                    (username, password_hash, salt, role, email, rsa_private_key, rsa_public_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (username, password_hash, salt, role, email, private_key, public_key)
                )
                new_user_id = cursor.lastrowid

                #Send OTP for Email Verification upon registration
                otp = generate_otp()
                expiry = int(time.time()) + 300 # 5 minutes
                cursor.execute(
                    "UPDATE users SET otp = ?, otp_expiry = ? WHERE id = ?",
                    (otp, expiry, new_user_id)
                )
        finally:
            conn.close()

        print(f"OTP for verification (demo): {otp}")
        send_otp_email(email, otp)
        log_action(new_user_id, role, "Registration", "User Account", "Success", f"User {username} registered. Verification OTP sent.")
        return redirect(f"/verify-otp/{new_user_id}")

    return render_template("register.html")


#FLOW : 
"""
GET /register 
   ↓
Show register.html form
   ↓
User submits form (POST)
   ↓
Extract form data
   ↓
Generate salt
   ↓
Hash password
   ↓
Store user in database
   ↓
Redirect to /login
"""

@auth_bp.route("/login", methods=["GET", "POST"])
#this route authenticates a user
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db", timeout=5)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, password_hash, salt FROM users WHERE username = ?",
                    (username,)
                )

                user = cursor.fetchone()
                if user:
                    user_id, stored_hash, salt = user
                    if verify_password(stored_hash, password, salt):
                        otp = generate_otp()
                        expiry = int(time.time()) + 300 #5 minutes

                        cursor.execute(
                            "UPDATE users SET otp = ? , otp_expiry = ? WHERE id = ?",
                            (otp,expiry,user_id)
                        )

                        print("OTP (for demo): ", otp)
                        
                        # Fetch email for sending OTP
                        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
                        user_email = cursor.fetchone()[0]
                        send_otp_email(user_email, otp)
                        
                        return redirect(f"/verify-otp/{user_id}")
                    else:
                        # Password mismatch
                        log_action(user_id, "Unknown", "Login", "Session", "Failure", f"Invalid password attempt for user: {username}")
                else:
                    # User doesn't exist
                    log_action(0, "Guest", "Login", "Session", "Failure", f"Login attempt with non-existent username: {username}")
        finally:
            conn.close()

        return render_template("alert.html", 
                               type="error", 
                               title="Access Denied", 
                               message="Invalid username or password. Please check your credentials and try again.",
                               back_url="/login",
                               back_label="Try Again")

    return render_template("login.html")

#this route verifies otp as second authentication factor
@auth_bp.route("/verify-otp/<int:user_id>", methods=["GET", "POST"])
def verify_otp(user_id):
    if request.method == "POST":
        entered_otp = request.form["otp"] #get otp entered by user

        conn = sqlite3.connect("database.db", timeout=5)
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT otp, otp_expiry, role FROM users WHERE id = ?",
                    (user_id,)
                )
                otp, expiry, role = cursor.fetchone()
                print("Stored OTP:", otp)
                print("Entered OTP:", entered_otp)
                print("Expiry:", expiry)
                print("Current time:", int(time.time()))

                if otp_valid(otp, entered_otp, int(expiry)):
                    #create session and store auth info
                    session["user_id"] = user_id
                    session["role"] = role
                    
                    log_action(user_id, role, "Login", "Session", "Success", f"MFA verification successful for {role}")
                    
                    if role == "Owner":
                        return redirect("/owner/dashboard")
                    elif role == "Executor":
                        return redirect("/executor/dashboard")
                    elif role == "Beneficiary":
                        return redirect("/beneficiary/dashboard")
                else:
                    log_action(user_id, role if role else "Unknown", "Login", "Session", "Failure", "Invalid or expired OTP entered")
        finally:
            conn.close()
        return render_template("alert.html", 
                               type="error", 
                               title="MFA Failure", 
                               message="The OTP entered is either invalid or has expired. Please try the login process again.",
                               back_url="/login",
                               back_label="Back to Login")

    return render_template("verify_otp.html")  