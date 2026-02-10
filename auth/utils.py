import hashlib #provides cryptographic hash functions like SHA-256
import os #to generate cryptographically secure random bytes
import random
import time

def generate_salt():
    return os.urandom(16).hex()
# generates 16 random bytes and converts bytes to readable hex string

def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()
#combine pwd with salt --> encode string to bytes as hash fn only work on bytes --> applies SHA-256 hashing algo --> returns readable hash string

def verify_password(stored_hash, password, salt):
    return stored_hash == hash_password(password, salt)
# user enters pwd --> system hashes it again using same salt --> compares new hash with stored hash


#SHA-256 is fast and secure and suitable for password hashing

def generate_otp():
    return str(random.randint(100000, 999999))

def otp_valid(stored_otp,entered_otp,expiry_time):
    if stored_otp != entered_otp :
        return False
    if time.time() > expiry_time:
        return False
    return True
