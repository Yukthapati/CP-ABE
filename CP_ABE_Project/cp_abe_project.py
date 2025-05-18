
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json

user_attributes_db = {
    "user1": ["Department:IT", "Role:Manager"],
    "user2": ["Department:HR", "Role:Analyst"],
    "user3": ["Department:IT", "Role:Developer"]
}

revoked_users = set()

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    encrypted = {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode()
    }
    return json.dumps(encrypted)

def decrypt_data(encrypted_json, key):
    encrypted = json.loads(encrypted_json)
    cipher = AES.new(key, AES.MODE_EAX, nonce=base64.b64decode(encrypted['nonce']))
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted['ciphertext']))
    try:
        cipher.verify(base64.b64decode(encrypted['tag']))
        return decrypted_data.decode()
    except ValueError:
        return "Decryption failed or data tampered!"

def has_access(user_id, required_attributes):
    if user_id in revoked_users:
        print(f"Access Denied for {user_id}: User is revoked.")
        return False
    user_attrs = user_attributes_db.get(user_id, [])
    return all(attr in user_attrs for attr in required_attributes)

def encrypt_file(data, policy_attributes):
    key = get_random_bytes(16)
    encrypted_data = encrypt_data(data, key)
    print(f"Data encrypted with policy: {policy_attributes}")
    return encrypted_data, key, policy_attributes

def attempt_decryption(user_id, encrypted_data, key, policy_attributes):
    if has_access(user_id, policy_attributes):
        result = decrypt_data(encrypted_data, key)
        print(f"{user_id} Decryption Result: {result}")
    else:
        print(f"{user_id} Access Denied: Attributes do not satisfy policy.")

def revoke_user(user_id):
    revoked_users.add(user_id)
    print(f"{user_id} has been revoked.")

if __name__ == "__main__":
    policy = ["Department:IT", "Role:Manager"]
    encrypted_data, encryption_key, applied_policy = encrypt_file("Confidential Cloud Data", policy)

    attempt_decryption("user1", encrypted_data, encryption_key, applied_policy)
    attempt_decryption("user2", encrypted_data, encryption_key, applied_policy)
    attempt_decryption("user3", encrypted_data, encryption_key, applied_policy)

    revoke_user("user1")
    attempt_decryption("user1", encrypted_data, encryption_key, applied_policy)
