
import random
import string
from cryptography.fernet import Fernet
import os
import json
import hashlib
import binascii
import re
from datetime import datetime

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

def validate_service_name(service):
    """Validate service name input."""
    if not service or not service.strip():
        return False, "Service name cannot be empty"
    
    if len(service.strip()) < 2:
        return False, "Service name must be at least 2 characters long"
    
    if service.strip() in passwords:
        return False, "Service already exists. Use a different name or update existing entry."
    
    return True, "Valid"

def add_password(service, password):
    # Validate service name
    is_valid, message = validate_service_name(service)
    if not is_valid:
        print(f"Error: {message}")
        return False
    
    # Analyze password strength
    display_password_analysis(password)
    
    # Ask for confirmation if password is weak
    score, strength, _ = analyze_password_strength(password)
    if strength == "Weak":
        confirm = input("This password is weak. Do you still want to save it? (y/N): ")
        if confirm.lower() not in ['y', 'yes']:
            print("Password not saved.")
            return False
    
    encrypted_password = fernet.encrypt(password.encode()).decode()
    passwords[service.strip()] = encrypted_password
    print(f"Password for {service.strip()} added.")
    return True

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
        if not save_passwords(): # Save after deletion
            print("Warning: Could not save passwords to file.")
    else:
        print(f"No password found for {service}.")

def list_services():
    if not passwords:
        print("No passwords stored yet.")
        return
    
    print("\nStored Services:")
    print("-" * 40)
    for i, service in enumerate(sorted(passwords.keys()), 1):
        print(f"{i}. {service}")
    print("-" * 40)
    print(f"Total: {len(passwords)} service(s)")

def analyze_password_strength(password):
    """Analyze password strength and return score and feedback."""
    score = 0
    feedback = []
    
    # Length check
    if len(password) < 8:
        feedback.append("Password is too short (minimum 8 characters)")
    elif len(password) >= 12:
        score += 2
        feedback.append("✓ Good length")
    else:
        score += 1
        feedback.append("✓ Adequate length")
    
    # Character variety checks
    if re.search(r'[a-z]', password):
        score += 1
        feedback.append("✓ Contains lowercase letters")
    else:
        feedback.append("✗ Missing lowercase letters")
    
    if re.search(r'[A-Z]', password):
        score += 1
        feedback.append("✓ Contains uppercase letters")
    else:
        feedback.append("✗ Missing uppercase letters")
    
    if re.search(r'\d', password):
        score += 1
        feedback.append("✓ Contains numbers")
    else:
        feedback.append("✗ Missing numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
        feedback.append("✓ Contains special characters")
    else:
        feedback.append("✗ Missing special characters")
    
    # Common patterns check
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("✗ Contains repeated characters")
    
    # Determine strength level
    if score >= 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Medium"
    else:
        strength = "Weak"
    
    return score, strength, feedback

def display_password_analysis(password):
    """Display password strength analysis."""
    score, strength, feedback = analyze_password_strength(password)
    
    print(f"\nPassword Strength Analysis:")
    print(f"Strength: {strength} (Score: {score}/6)")
    print("-" * 30)
    for item in feedback:
        print(f"  {item}")
    print("-" * 30)

def show_help():
    """Display help information and usage instructions."""
    print("\n" + "="*60)
    print("                    PASSWORD MANAGER HELP")
    print("="*60)
    print("\nFEATURES:")
    print("• Secure password storage with encryption")
    print("• Master password protection")
    print("• Password strength analysis")
    print("• Automatic password generation")
    print("• Service management (add, view, delete, list)")
    
    print("\nMENU OPTIONS:")
    print("1. Generate new password - Creates a random secure password")
    print("2. Add password - Manually add a password for a service")
    print("3. Get password - Retrieve a stored password")
    print("4. List all services - View all stored service names")
    print("5. Delete password - Remove a password for a service")
    print("6. Show help - Display this help information")
    print("7. Exit - Close the password manager")
    
    print("\nSECURITY FEATURES:")
    print("• All passwords are encrypted before storage")
    print("• Master password protects access to your vault")
    print("• Password strength analysis helps create secure passwords")
    print("• Confirmation prompts for destructive actions")
    
    print("\nBEST PRACTICES:")
    print("• Use strong, unique passwords for each service")
    print("• Keep your master password secure and memorable")
    print("• Regularly backup your password file")
    print("• Don't share your master password with anyone")
    
    print("\n" + "="*60)
    input("Press Enter to return to the main menu...")

def save_passwords():
    try:
        with open(PASSWORD_FILE, "w") as f:
            json.dump(passwords, f, indent=2)
        print("Passwords saved to file.")
        return True
    except PermissionError:
        print("Error: Permission denied. Cannot write to password file.")
        return False
    except Exception as e:
        print(f"Error saving passwords: {e}")
        return False

def load_passwords():
    global passwords
    try:
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as f:
                passwords = json.load(f)
            print("Passwords loaded from file.")
        else:
            print("No password file found. Starting with an empty password list.")
            passwords = {}
        return True
    except PermissionError:
        print("Error: Permission denied. Cannot read password file.")
        passwords = {}
        return False
    except json.JSONDecodeError:
        print("Error: Password file is corrupted. Starting with empty password list.")
        passwords = {}
        return False
    except Exception as e:
        print(f"Error loading passwords: {e}")
        passwords = {}
        return False

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
    
    # Load passwords at startup
    if not load_passwords():
        print("Warning: Could not load passwords. Some features may not work correctly.")

    while True:
        print("\n" + "="*50)
        print("           PASSWORD MANAGER")
        print("="*50)
        print("1. Generate new password")
        print("2. Add password")
        print("3. Get password")
        print("4. List all services")
        print("5. Delete password")
        print("6. Show help")
        print("7. Exit")
        print("-"*50)

        choice = input("Enter your choice (1-7): ")

        if choice == '1':
            try:
                length = int(input("Enter password length (default 12): ") or 12)
                if length < 4 or length > 100:
                    print("Password length must be between 4 and 100 characters.")
                    continue
                new_password = generate_password(length)
                print(f"Generated password: {new_password}")
                service = input("Enter service name to save this password: ")
                if add_password(service, new_password):
                    if not save_passwords(): # Save after adding
                        print("Warning: Could not save passwords to file.")
            except ValueError:
                print("Invalid length. Please enter a number.")
        elif choice == '2':
            service = input("Enter service name: ")
            password = input("Enter password: ")
            if add_password(service, password):
                if not save_passwords(): # Save after adding
                    print("Warning: Could not save passwords to file.")
        elif choice == '3':
            service = input("Enter service name: ")
            get_password(service)
        elif choice == '4':
            list_services()
        elif choice == '5':
            service = input("Enter service name to delete: ")
            confirm = input(f"Are you sure you want to delete password for '{service}'? (y/N): ")
            if confirm.lower() in ['y', 'yes']:
                delete_password(service)
            else:
                print("Deletion cancelled.")
        elif choice == '6':
            show_help()
        elif choice == '7':
            print("\nExiting Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
