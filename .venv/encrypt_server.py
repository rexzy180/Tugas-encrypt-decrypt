from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

app = Flask(__name__)

# Load public key dari file
with open("keys/public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Route untuk enkripsi
@app.route("/encrypt", methods=["POST"])
def encrypt_message():
    data = request.get_json()  # Ambil JSON dari Postman
    message = data.get("message", "").encode("utf-8")

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encoded = base64.b64encode(ciphertext).decode("utf-8")
    return jsonify({"ciphertext": encoded})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
