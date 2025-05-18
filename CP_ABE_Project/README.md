
# CP-ABE Cloud Data Sharing Simulation

This project simulates Ciphertext-Policy Attribute-Based Encryption (CP-ABE) using AES encryption and attribute-based access control in Python.

## How It Works

- Encrypts data with a set of attribute-based access policies.
- Allows decryption for users whose attributes match the policy.
- Revokes user access by adding them to a revocation list.
- Demonstrates encryption, decryption, and revocation functionality.

## Dependencies

Install required Python package:

```
pip install pycryptodome
```

## Running the Project

Execute the script using:

```
python cp_abe_project.py
```

## Files

- `cp_abe_project.py` : Main Python implementation
- `README.md`         : Project instructions and explanation
