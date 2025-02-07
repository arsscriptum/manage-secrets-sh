<center><img src="doc/img/banner2.jpg" alt="banner2"></center>

# Secure Secrets Management System

This project provides a secure way to manage secrets (such as passwords and sensitive data) using both asymmetric and symmetric encryption. The system first generates an Ed25519 key pair, then uses AES encryption to secure data. The AES key is further encrypted using the Ed25519 public key, ensuring layered security.

## Features
- Uses **Ed25519** for asymmetric encryption
- Uses **AES encryption** for securing sensitive data
- Encrypts AES keys with the Ed25519 public key
- Stores encrypted files in the home directory
- Implements logging and validation checks

## Installation

Ensure that the required dependencies are installed on your system:

```bash
sudo apt update
sudo apt install -y openssl aescrypt
```

The script will also attempt to install `age` if it is missing.

## Usage

### 1. Generate Keys & Encrypt Data
Run the following script to initialize the encryption system:

```bash
sudo bash secrets-manager.sh
```

The script will:
- Generate an Ed25519 private and public key pair
- Create a secure AES key file
- Encrypt the AES key using the Ed25519 public key

### 2. Encrypting and Decrypting Data

Once the keys are generated, data can be securely encrypted and decrypted.

#### Encrypting a File
```bash
aescrypt -e -k ~/.secrets/.keys/<username>-aes.key -o encrypted_data.aes plaintext.txt
```

#### Decrypting a File
```bash
aescrypt -d -k ~/.secrets/.keys/<username>-aes.key -o decrypted_data.txt encrypted_data.aes
```

### 3. Securely Storing the AES Key
The AES key is encrypted using the Ed25519 public key:
```bash
age -R ~/.secrets/.keys/<username>-ed25pub.pem -o ~/.secrets/.keys/<username>-aes.enc ~/.secrets/.keys/<username>-aes.key
```

### 4. Decrypting the AES Key
If needed, the AES key can be recovered:
```bash
age -d -i ~/.secrets/.keys/<username>-ed25prv.pem -o ~/.secrets/.keys/<username>-aes.key ~/.secrets/.keys/<username>-aes.enc
```

## File Structure

The script organizes files in the following directories:

```
~/.secrets/
    ├── .keys/             # Storage for encryption keys
    │   ├── <user>-ed25prv.pem  # Ed25519 Private Key
    │   ├── <user>-ed25pub.pem  # Ed25519 Public Key
    │   ├── <user>-aes.key      # AES Key (plaintext)
    │   ├── <user>-aes.enc      # AES Key (encrypted)
    ├── credentials/        # Encrypted credential files
```

## Security Considerations
- **Private keys should never be shared or stored in an insecure location.**
- **Backup encrypted AES keys separately from their corresponding private keys.**
- **Use strong passphrases when encrypting additional data.**

## Logs
The script maintains logs at:
```bash
~/.secrets/logs/secret-mgt.log
```


<center><img src="doc/img/secrets_2.png" alt="banner3"></center>
