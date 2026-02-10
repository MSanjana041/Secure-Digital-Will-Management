import smtplib
from email.mime.text import MIMEText
import os

GMAIL_USER = "cbscu4cse@gmail.com"
GMAIL_APP_PASSWORD = "yqjwxgrnavfgalrg"

def send_otp_email(receiver_email, otp):
    """
    Sends a 6-digit OTP to the specified email using Gmail SMTP.
    """
    if GMAIL_USER == "your-email@gmail.com":
        print(f"⚠️ EMAIL NOT CONFIGURED. Print OTP for testing: {otp}")
        return

    msg = MIMEText(f"Your Secure Digital Will Verification Code is: {otp}\n\nThis code will expire in 5 minutes.")
    msg['Subject'] = "Secure Digital Will - OTP Verification"
    msg['From'] = GMAIL_USER
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)
            print(f"✅ OTP Email sent successfully to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
