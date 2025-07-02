from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import base64, json, datetime

# Load private key receiver và public key sender
with open("rsa_keys/receiver_private.pem", "rb") as f:
    receiver_priv = RSA.import_key(f.read())
with open("rsa_keys/sender_public.pem", "rb") as f:
    sender_pub = RSA.import_key(f.read())

# Đọc encrypted.json
with open("encrypted.json", "r") as f:
    data = json.load(f)

# Giải mã session key
enc_key = base64.b64decode(data["session_key"])
cipher_rsa = PKCS1_v1_5.new(receiver_priv)
sentinel = b"timeout"
session_key = cipher_rsa.decrypt(enc_key, sentinel)

# Kiểm tra hạn
exp = datetime.datetime.strptime(data["exp"], "%Y-%m-%dT%H:%M:%SZ")
now = datetime.datetime.utcnow()
if now > exp:
    print("❌ Quá hạn! Không giải mã.")
    exit()

# Xác thực chữ ký
iv = base64.b64decode(data["iv"])
ciphertext = base64.b64decode(data["cipher"])
sig = base64.b64decode(data["sig"])
hash_val = SHA512.new(iv + ciphertext + data["exp"].encode())

try:
    pkcs1_15.new(sender_pub).verify(hash_val, sig)
    print("✅ Chữ ký hợp lệ.")
except (ValueError, TypeError):
    print("❌ Chữ ký không hợp lệ.")
    exit()

# Giải mã AES
cipher = AES.new(session_key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext).rstrip(b"\0")

# Lưu file đã giải mã
with open("email_decrypted.txt", "wb") as f:
    f.write(plaintext)

print("✅ Đã giải mã và lưu vào email_decrypted.txt")