import os
from Crypto.PublicKey import RSA

# Tạo thư mục nếu chưa có
os.makedirs("rsa_keys", exist_ok=True)

def generate_keys(name):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"rsa_keys/{name}_private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open(f"rsa_keys/{name}_public.pem", "wb") as pub_file:
        pub_file.write(public_key)

generate_keys("sender")
generate_keys("receiver")

print("✅ Đã tạo khóa sender và receiver trong thư mục rsa_keys")