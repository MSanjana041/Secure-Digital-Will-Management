import datetime
from flask import Flask , session , redirect ,render_template
from auth.auth_routes import auth_bp
from will.will_routes import will_bp
from auth.audit import log_action
import sqlite3

app = Flask(__name__)
app.secret_key = "replace_this_later"

app.register_blueprint(auth_bp)
app.register_blueprint(will_bp)

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect("/login")

    role = session.get("role")

    if role == "Owner":
        return redirect("/owner/dashboard")
    elif role == "Executor":
        return redirect("/executor/dashboard")
    elif role == "Beneficiary":
        return redirect("/beneficiary/dashboard")
    else:
        session.clear()
        return redirect("/login")


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], session["role"], "Logout", "Session", "Success", "User session terminated")
    session.clear()
    return redirect("/login")

@app.route("/debug-session")
def debug_session():
    return dict(session)

@app.route("/owner/dashboard")
def owner_dashboard():
    if session.get("role") != "Owner":
        return redirect("/login")
    
    # 📊 Fetch stats for owner
    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()
            
            # Count testaments created by this owner
            cursor.execute("SELECT COUNT(*) FROM wills WHERE owner_id = ?", (session["user_id"],))
            testaments_count = cursor.fetchone()[0]
            
            # Count beneficiaries (mock data logic or from potential table)
            # Since we don't have a beneficiaries table linked yet, we mock this for the UI or fetch all beneficiaries
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'Beneficiary'")
            beneficiaries_count = cursor.fetchone()[0] # In a real app, this would be linked to the specific will
    finally:
        conn.close()
    
    last_updated = datetime.datetime.now().strftime("%b %d")

    return render_template("owner/dashboard.html", 
                           testaments_count=testaments_count, 
                           beneficiaries_count=beneficiaries_count,
                           last_updated=last_updated)


@app.route("/executor/dashboard")
def executor_dashboard():
    if session.get("role") != "Executor":
        return redirect("/login")
    
    # 📊 Fetch stats for executor (simulated)
    # In real app: SELECT COUNT(*) FROM wills WHERE executor_id = ...
    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()
            
            # Total wills assigned (Total wills in system for demo)
            cursor.execute("SELECT COUNT(*) FROM wills")
            wills_assigned_count = cursor.fetchone()[0]
            
            # Released wills
            cursor.execute("SELECT COUNT(*) FROM wills WHERE is_released = 1")
            released_count = cursor.fetchone()[0]
    finally:
        conn.close()
    
    pending_count = wills_assigned_count - released_count

    return render_template("executor/dashboard.html",
                           wills_assigned_count=wills_assigned_count,
                           released_count=released_count,
                           pending_count=pending_count)


@app.route("/beneficiary/dashboard")
def beneficiary_dashboard():
    if session.get("role") != "Beneficiary":
        return redirect("/login")
    
    # 📊 Check release status
    is_released = False
    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()
            
            # Check if ANY will is released (simplification for single-will demo)
            cursor.execute("SELECT is_released FROM wills LIMIT 1")
            row = cursor.fetchone()
            if row and row[0] == 1:
                is_released = True
    finally:
        conn.close()

    return render_template("beneficiary/dashboard.html", is_released=is_released)


if __name__ == "__main__":
    app.run(debug=True,use_reloader=False)