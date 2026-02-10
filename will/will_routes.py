from flask import Blueprint, session , request , render_template , redirect
import sqlite3 , ast, time #to fetch will data
from will.access_control import can_access #authorization policy
from will.crypto import (
    encrypt_aes, decrypt_aes,
    generate_rsa_keys, encrypt_key_rsa, decrypt_key_rsa,
    sign_data, verify_signature
)
from auth.audit import log_action



will_bp = Blueprint("will", __name__)

@will_bp.route("/view-will")
def view_will():
    if "user_id" not in session:
        return render_template("alert.html", 
                               type="error", 
                               title="Access Denied", 
                               message="You must be logged in to view testament documents.",
                               back_url="/login",
                               back_label="Login"), 403

    role = session["role"]
    user_id = session["user_id"]

    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()

            # 1. Determine which wills to fetch based on role
            if role == "Owner":
                # Owner sees ONLY their created wills
                cursor.execute("SELECT id, owner_id, encrypted_will, encrypted_aes_key, signature, is_released FROM wills WHERE owner_id = ?", (user_id,))
            elif role == "Executor" or role == "Beneficiary":
                 # In a real app, executors/beneficiaries would be linked to specific wills.
                 # For this demo, we fetch ALL wills but only decrypt if `is_released` (or if check passes).
                 # Note: can_access() check logic handles the specific permissions, we just fetch candidates here.
                 cursor.execute("SELECT id, owner_id, encrypted_will, encrypted_aes_key, signature, is_released FROM wills")
            
            rows = cursor.fetchall()

            decrypted_wills = []

            for row in rows:
                will_id, owner_id, encrypted_will_str, encrypted_aes_key, signature, is_released = row

                # 2. Check Access Policy
                if not can_access(role, "will", "read", is_released):
                    continue # Skip wills user isn't allowed to see

                # 3. Fetch Owner's Keys for Decryption
                cursor.execute("SELECT username, rsa_private_key, rsa_public_key FROM users WHERE id = ?", (owner_id,))
                key_row = cursor.fetchone()
                
                if not key_row or not key_row[1] or not key_row[2]:
                     continue # Cannot decrypt without keys

                owner_name, private_key, public_key = key_row

                try:
                    # 4. Decrypt Process
                    encrypted_will = ast.literal_eval(encrypted_will_str)
                    aes_key = decrypt_key_rsa(encrypted_aes_key, private_key)
                    will_text = decrypt_aes(encrypted_will, aes_key)
                    
                    # 5. Verify Signature
                    is_valid = verify_signature(will_text, signature, public_key)
                    
                    decrypted_wills.append({
                        "id": will_id,
                        "signer": owner_name,
                        "content": will_text,
                        "verified": is_valid
                    })
                except Exception as e:
                    print(f"Error decrypting will {will_id}: {e}")
                    continue
    finally:
        conn.close()

    log_action(user_id, role, "Access", "Will Document", "Success", f"User viewed {len(decrypted_wills)} decrypted testaments")
    return render_template("view_wills.html", wills=decrypted_wills)


@will_bp.route("/release-will")
#privileged action - only executor can change state by releasing will and unlock access for beneficiaries
def release_will():
    if "user_id" not in session:
        return render_template("alert.html", 
                               type="error", 
                               title="Access Denied", 
                               message="Unauthorized access attempt detected.",
                               back_url="/login"), 403

    # Role Based Access Control (RBAC)
    if session["role"] != "Executor":
        return render_template("alert.html", 
                               type="error", 
                               title="Privilege Required", 
                               message="Only the designated Executor is authorized to release these sensitive testament documents."), 403

    will_id = request.args.get("id")
    if not will_id:
        return render_template("alert.html", 
                               type="error", 
                               title="Error", 
                               message="No Will ID provided."), 400

    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE wills SET is_released = 1 WHERE id = ? AND is_released = 0", (will_id,))
            #updates will status as released
    finally:
        conn.close()

    log_action(session["user_id"], session["role"], "Authorize Release", "Will Document", "Success", f"Executor released testament ID: {will_id}")
    return render_template("alert.html", 
                           type="success", 
                           title="Will Released", 
                           message="The testament document has been successfully released. Designated beneficiaries can now access their inheritance information.",
                           back_url="/executor/dashboard",
                           back_label="Back to Portal")

#WILL CREATION - OWNER ONLY
@will_bp.route("/create-will", methods=["GET", "POST"])
def create_will():
    if session.get("role") != "Owner":
        return render_template("alert.html", 
                               type="error", 
                               title="Unauthorized", 
                               message="Only testament owners are authorized to create new digital wills."), 403

    if request.method == "POST":
        will_text = request.form["will"]

        # 🔐 Step 1: Encrypt will using AES
        encrypted, aes_key = encrypt_aes(will_text)

        conn = sqlite3.connect("database.db", timeout=5)
        try:
            with conn:
                cursor = conn.cursor()

                # 🔑 Step 2: Fetch owner's RSA keys (PERSISTENT)
                cursor.execute(
                    "SELECT rsa_private_key, rsa_public_key FROM users WHERE id = ?",
                    (session["user_id"],)
                )
                row = cursor.fetchone()

                if not row or not row[0] or not row[1]:
                    return "Owner RSA keys not found", 500

                private_key, public_key = row

                # 🔐 Step 3: Encrypt AES key using owner's PUBLIC key
                encrypted_key = encrypt_key_rsa(aes_key, public_key)

                # ✍️ Step 4: Sign will using owner's PRIVATE key
                signature = sign_data(will_text, private_key)

                # 💾 Step 5: Store everything
                cursor.execute(
                    """
                    INSERT INTO wills 
                    (owner_id, encrypted_will, encrypted_aes_key, signature) 
                    VALUES (?, ?, ?, ?)
                    """,
                    (session["user_id"], str(encrypted), encrypted_key, signature)
                )
        finally:
            conn.close()

        log_action(session["user_id"], "Owner", "Create", "Will Document", "Success", "Owner created and encrypted a new digital testament")
        return redirect("/owner/dashboard")

    
    return render_template("create_will.html")



@will_bp.route("/authorize-release")
def authorize_release_page():
    if session.get("role") != "Executor":
        return "Unauthorized", 403
    
    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()
            # Fetch pending wills with owner names
            cursor.execute("""
                SELECT w.id, u.username 
                FROM wills w 
                JOIN users u ON w.owner_id = u.id 
                WHERE w.is_released = 0
            """)
            pending_wills = []
            for row in cursor.fetchall():
                pending_wills.append({
                    "id": row[0],
                    "owner": row[1]
                })
    finally:
        conn.close()
    
    if not pending_wills:
        return render_template("alert.html", 
                               type="success", 
                               title="No Action Needed", 
                               message="All assigned digital wills have already been authorized and released.",
                               back_url="/executor/dashboard")
        
    return render_template("executor/authorize_release.html", wills=pending_wills) 

@will_bp.route("/audit-trail")
def audit_trail():
    if "user_id" not in session:
        return redirect("/login")
        
    user_id = session["user_id"]
    role = session["role"]
    
    conn = sqlite3.connect("database.db", timeout=5)
    try:
        with conn:
            cursor = conn.cursor()
            
            # 🔍 Fetch logs
            # For Owner: Sees logs related to THEIR will (all roles actions on it) or their own actions.
            # For Executor/Owner: For demo, let's show all logs but properly filtered.
            if role in ["Owner", "Executor"]:
                # Owners and Executors can see all logs for security oversight
                cursor.execute("""
                    SELECT a.id, COALESCE(u.username, 'Guest/Unknown'), a.role, a.action, a.resource, a.status, a.timestamp, a.ip_address, a.details
                    FROM audit_logs a
                    LEFT JOIN users u ON a.user_id = u.id
                    ORDER BY a.timestamp DESC
                """)
            else:
                # Others see only their own actions for privacy
                cursor.execute("""
                    SELECT a.id, u.username, a.role, a.action, a.resource, a.status, a.timestamp, a.ip_address, a.details
                    FROM audit_logs a
                    LEFT JOIN users u ON a.user_id = u.id
                    WHERE a.user_id = ?
                    ORDER BY a.timestamp DESC
                """, (user_id,))
                
            rows = cursor.fetchall()
    finally:
        conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            "id": row[0],
            "username": row[1],
            "role": row[2],
            "action": row[3],
            "resource": row[4],
            "status": row[5],
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row[6])),
            "ip": row[7],
            "details": row[8]
        })

    return render_template("audit_trail.html", logs=logs)
