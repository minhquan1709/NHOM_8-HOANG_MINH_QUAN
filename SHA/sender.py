from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import base64, json, datetime

# Load public key receiver và private key sender
with open("rsa_keys/receiver_public.pem", "rb") as f:
    receiver_pub = RSA.import_key(f.read())
with open("rsa_keys/sender_private.pem", "rb") as f:
    sender_priv = RSA.import_key(f.read())

# Tạo session key và iv AES
session_key = get_random_bytes(32)
iv = get_random_bytes(16)

# Đọc email.txt
with open("email.txt", "rb") as f:
    plaintext = f.read()

# AES-CBC
cipher = AES.new(session_key, AES.MODE_CBC, iv)

# Padding
pad = lambda s: s + b"\0" * (AES.block_size - len(s) % AES.block_size)
ciphertext = cipher.encrypt(pad(plaintext))

# Tạo exp_time +24h (UTC)
exp_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

# Hash SHA-512 bao gồm iv + ciphertext + exp_time
hash_val = SHA512.new(iv + ciphertext + exp_time.encode())
signature = pkcs1_15.new(sender_priv).sign(hash_val)

# Mã hóa session key bằng RSA receiver public key
cipher_rsa = PKCS1_v1_5.new(receiver_pub)
enc_session_key = cipher_rsa.encrypt(session_key)

# Gói tin
payload = {
    "iv": base64.b64encode(iv).decode(),
    "cipher": base64.b64encode(ciphertext).decode(),
    "hash": hash_val.hexdigest(),
    "sig": base64.b64encode(signature).decode(),
    "exp": exp_time,
    "session_key": base64.b64encode(enc_session_key).decode()
}

# Ghi ra encrypted.json
with open("encrypted.json", "w") as f:
    json.dump(payload, f, indent=4)

print(f"✅ Đã tạo encrypted.json với hạn dùng đến {exp_time}")