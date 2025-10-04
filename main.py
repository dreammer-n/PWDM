
import random
import string
from cryptography.fernet import Fernet
import os
import json
import hashlib
import binascii

passwords = {}
key = None
fernet = None
PASSWORD_FILE = "passwords.json"
MASTER_PASSWORD_FILE = "master.key"

def write_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def add_password(service, password):
    encrypted_password = fernet.encrypt(password.encode()).decode()
    passwords[service] = encrypted_password
    print(f"Password for {service} added.")

def get_password(service):
    encrypted_password = passwords.get(service)
    if encrypted_password:
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
        print(f"Password for {service}: {decrypted_password}")
    else:
        print(f"No password found for {service}.")

def delete_password(service):
    if service in passwords:
        del passwords[service]
        print(f"Password for {service} deleted.")
        save_passwords() # Save after deletion
    else:
        print(f"No password found for {service}.")

def save_passwords():
    with open(PASSWORD_FILE, "w") as f:
        json.dump(passwords, f)
    print("Passwords saved to file.")

def load_passwords():
    global passwords
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as f:
            passwords = json.load(f)
        print("Passwords loaded from file.")
    else:
        print("No password file found. Starting with an empty password list.")

def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000
    )
    return salt + key

def verify_password(stored_password, provided_password):
    salt = stored_password[:32]
    stored_key = stored_password[32:]
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        provided_password.encode('utf-8'), 
        salt, 
        100000
    )
    return stored_key == key

def main():
    global key, fernet

    if not os.path.exists(MASTER_PASSWORD_FILE):
        master_password = input("Set your master password: ")
        hashed_master_password = hash_password(master_password)
        with open(MASTER_PASSWORD_FILE, "wb") as f:
            f.write(hashed_master_password)
        print("Master password set.")
    
    # Master password authentication
    max_attempts = 3
    attempts = 0
    while attempts < max_attempts:
        entered_master_password = input("Enter master password: ")
        with open(MASTER_PASSWORD_FILE, "rb") as f:
            stored_hashed_master_password = f.read()
        
        if verify_password(stored_hashed_master_password, entered_master_password):
            print("Authentication successful.")
            break
        else:
            attempts += 1
            print(f"Incorrect master password. {max_attempts - attempts} attempts remaining.")
    else:
        print("Too many incorrect attempts. Exiting.")
        return

    if not os.path.exists("secret.key"):
        write_key()
    key = load_key()
    fernet = Fernet(key)
    load_passwords() # Load passwords at startup

    while True:
        print("\nPassword Manager Menu:")
        print("1. Generate new password")
        print("2. Add password")
        print("3. Get password")
        print("4. Delete password")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            try:
                length = int(input("Enter password length (default 12): ") or 12)
                new_password = generate_password(length)
                print(f"Generated password: {new_password}")
                service = input("Enter service name to save this password: ")
                add_password(service, new_password)
                save_passwords() # Save after adding
            except ValueError:
                print("Invalid length. Please enter a number.")
        elif choice == '2':
            service = input("Enter service name: ")
            password = input("Enter password: ")
            add_password(service, password)
            save_passwords() # Save after adding
        elif choice == '3':
            service = input("Enter service name: ")
            get_password(service)
        elif choice == '4':
            service = input("Enter service name: ")
            delete_password(service)
        elif choice == '5':
            print("Exiting Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
