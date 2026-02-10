# 🔐 Secure Digital Will Management System

A secure web-based application designed to digitally manage wills and inheritance workflows using **modern security principles**, **cryptographic protections**, and **role-based access control**.

This project was developed as part of the **Foundations of Cyber Security Lab**, with emphasis on **confidentiality, integrity, authentication, authorization, and accountability**.

---

##  Problem Statement

Traditional will management systems are vulnerable to:

- Unauthorized access  
- Premature disclosure  
- Data tampering  
- Lack of accountability  

This system addresses these issues by securely storing digital wills and enforcing controlled access based on clearly defined roles.

---

##  User Roles

The system supports three distinct roles:

- **Owner (Testator)** – Creates and digitally signs the will  
- **Executor** – Verifies and authorizes the release of the will  
- **Beneficiary** – Gains access only after the will is released  

Each role has **strictly limited permissions**, enforced at the backend.

---

## 🔐 Security Concepts Implemented

### 1. Authentication & Multi-Factor Authentication (MFA)

- Username and password-based login  
- Passwords are **salted and hashed** before storage  
- OTP-based second factor authentication  
- Sessions are created **only after OTP verification**

**Security Principle:** Defense in Depth

---

### 2. Role-Based Access Control (RBAC)

- Access decisions are based on the user’s role stored in the session  
- Every sensitive route performs a backend role check  
- UI elements reflect permissions, but **backend always enforces rules**

**Security Principles:** Least Privilege & Separation of Duties

---

### 3. Hybrid Encryption (Confidentiality)

The will content is protected using **hybrid cryptography**:

- **AES (Symmetric Encryption)**  
  - Encrypts the will content efficiently  

- **RSA (Asymmetric Encryption)**  
  - Encrypts the AES key using the owner’s public key  

Plaintext will data is **never stored** in the database.

**Security Principle:** Confidentiality

---

### 4. Digital Signatures (Integrity & Authenticity)

- The will is digitally signed using the **owner’s RSA private key**  
- Signature verification is performed using the **public key**  
- Any tampering results in verification failure and access denial  

**Security Principles:** Integrity & Non-Repudiation

---

### 5. Controlled Release Mechanism

- Wills maintain a release state (`is_released`)  
- Only the **executor** can authorize the release  
- Beneficiaries gain access **only after release**

**Security Principle:** Conditional Authorization

---

### 6. Audit Logging (Accountability)

All security-critical actions are logged, including:

- Login attempts  
- OTP verification  
- Will creation  
- Will release  
- Access attempts (successful & denied)  
- Logout events  

Audit logs are **read-only** and accessible only to authorized roles.

**Security Principle:** Accountability & Traceability

---

##  Secure Design Principles Used

- Least Privilege  
- Separation of Duties  
- Defense in Depth  
- Secure Key Management  
- Secure by Design  
- Fail-Secure Defaults  

---

## 🛠 Tech Stack

### Backend
- Python  
- Flask  
- SQLite3  

### Cryptography
- AES (256-bit) for data encryption  
- RSA (Public/Private Key) for key protection  
- RSA-PSS Digital Signatures  
- SHA-256 hashing  

### Frontend
- HTML  
- CSS (role-specific stylesheets)

### Tools
- DB Browser for SQLite  
- Git & GitHub  

---

## 🧪 Demo Environment

- Application is demonstrated **locally**  
- OTP delivery is simulated via **terminal output**  
- External Email/SMS services are intentionally avoided for academic clarity  

---