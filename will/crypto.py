from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64


def encrypt_aes(data):
    key = get_random_bytes(16)  # AES-128
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    encrypted = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

    return encrypted, key


def decrypt_aes(encrypted, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=base64.b64decode(encrypted["nonce"]))
    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(encrypted["ciphertext"]),
        base64.b64decode(encrypted["tag"])
    )
    return plaintext.decode()


def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()


def encrypt_key_rsa(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(aes_key)


def decrypt_key_rsa(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_key)


def sign_data(data, private_key):
    rsa_key = RSA.import_key(private_key)
    h = SHA256.new(data.encode())
    signer = pss.new(rsa_key)
    signature = signer.sign(h)
    return signature

def verify_signature(data, signature, public_key):
    rsa_key = RSA.import_key(public_key)
    h = SHA256.new(data.encode())
    verifier = pss.new(rsa_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
