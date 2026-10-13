"""
Islamic University of Gaza - Faculty of Information Technology
Department of Software Development
Course: Software Security (SDEV 4303) - 1st Semester 2026/2027
Instructor: Dr. Abdelkareem Alashqar

Assignment 1: Chapter 02 – Cryptographic Tools
Part C: RSA Digital Signature Implementation

Student Name: Mohamed Rani Abu Sadaa
Student ID: 120231584
"""

import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def verify_message(pub_key, message_bytes, sig_bytes):
    """
    Verifies a digital signature using the sender's public key.
    Returns VALID if authentic, or INVALID if modified/forged.
    """
    try:
        pub_key.verify(
            sig_bytes,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "VALID (Integrity and Origin Authenticated)"
    except InvalidSignature:
        return "INVALID (Tampering or Forgery Detected!)"


def main():
    # 1. Key Generation (2048-bit key modulus)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    print("[+] RSA 2048-bit Key Pair Generated Successfully.")

    # 2. Message to Sign
    original_message = b"Islamic University of Gaza - SDEV 4303 Assignment: Chapter 2"
    print(f"[+] Original Message: {original_message}")

    # 3. Signature Generation (SHA-256 with PSS Padding)
    signature = private_key.sign(
        original_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    sig_hex = binascii.hexlify(signature).decode()
    print(f"[+] Signature (Hex Prefix): {sig_hex[:40]}... [Length: {len(signature)} bytes]\n")

    # --- Verification Test 1: Authentic Message ---
    print("--- Verification Test 1: Authentic Message ---")
    print("Testing verification on original message...")
    result_1 = verify_message(public_key, original_message, signature)
    print(f"Result: {result_1}\n")

    # --- Verification Test 2: Tampered Message (Integrity Violation) ---
    print("--- Verification Test 2: Tampered Message (Integrity Violation) ---")
    tampered_message = b"Islamic University of Gaza - SDEV 4303 Assignment: Chapter 2 [MODIFIED]"
    print(f"Tampered Message: {tampered_message}")
    print("Testing verification on modified message...")
    result_2 = verify_message(public_key, tampered_message, signature)
    print(f"Result: {result_2}")


if __name__ == "__main__":
    main()