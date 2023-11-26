import json
import jwt
import datetime

# # issued_at time
# iat = datetime.datetime.utcnow()
# # expire time
# exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=100))

# JWT payload
payload = {
    "sub": "1234567", # Subject (User ID)
    "iss": "your-app", # Issuer
    "audience": "your-api", # Audience
    "exp": int((datetime.datetime.utcnow() + datetime.timedelta(hours=100)).timestamp()), # Expiration (1 hour from now)
    "custom_claim": "some_value", # Custom claim
    "user_role": "admin" # Custom user role claim
}

print(f"payload = {payload}")

# Your secret key for signing the token (keep this secret)
secret_key = "your-secret-key"

# Create the JWT token
token = jwt.encode(payload=payload,
                   key='secret',
                   algorithm='HS256')

print(f"encoded token = {token}")




#####################
# Decoding
try:
    # Decode and verify the token
    decode_payload = jwt.decode(jwt=token,
                                key='secret',
                                algorithms=['HS256'])

    # The decoded_payload now contains the claims from the token
    print(f"Decoded token = {decode_payload}")
except jwt.ExpiredSignatureError:
    # Handle token expiration
    print("Token has expired")
except jwt.exceptions.PyJWTError as e:
    # Handle other JWT errors
    print(e)
    print("Invalid token")