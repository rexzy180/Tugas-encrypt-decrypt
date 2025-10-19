from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

# Folder tempat penyimpanan kunci
KEY_DIR = "keys"
os.makedirs(KEY_DIR, exist_ok=True)

# Generate private key 4096-bit
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# Simpan private key ke file private.pem
with open(os.path.join(KEY_DIR, "private.pem"), "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Generate public key dari private key
public_key = private_key.public_key()

# Simpan public key ke file public.pem
with open(os.path.join(KEY_DIR, "public.pem"), "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("✅ Kunci RSA berhasil dibuat!")
print(" - Private key: keys/private.pem")
print(" - Public key : keys/public.pem")
