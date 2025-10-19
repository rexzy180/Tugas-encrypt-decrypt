from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

app = Flask(__name__)

# Load private key dari file
with open("keys/private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None  # Kalau key kamu punya password, masukkan di sini
    )

# Route untuk dekripsi
@app.route("/decrypt", methods=["POST"])
def decrypt_message():
    data = request.get_json()
    ciphertext_b64 = data.get("ciphertext", "")
    
    try:
        # Decode base64
        ciphertext = base64.b64decode(ciphertext_b64)

        # Dekripsi menggunakan private key
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return jsonify({
            "plaintext": plaintext.decode("utf-8")
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
