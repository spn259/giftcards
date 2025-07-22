from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64

# 1) Create an EC key (prime256v1 / P-256)
key = ec.generate_private_key(ec.SECP256R1())

# 2) Extract private key (PEM)
priv = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# 3) Extract public key (uncompressed point)
pub_key = key.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# 4) Base64-URL encode (no padding) for Web Push
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

vapid_public  = b64url(pub_key)
vapid_private = b64url(
    key.private_numbers().private_value.to_bytes(32, "big")
)

print("VAPID_PUBLIC_KEY =", vapid_public)
print("VAPID_PRIVATE_KEY =", vapid_private)
