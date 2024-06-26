#!/usr/bin/python3

# SecureVault 1.0
# Author: WhiteHack

from secrets import choice
from sys import argv
from os import system, path, mkdir, remove, listdir
from cryptography.fernet import Fernet
from hashlib import sha3_512
from getpass import getpass, getuser


class SecureVault:

    def __init__(self):
        self.symbols_and_numbers = ["@", "1", "/", "*", "8", "_", "6", "0", "'", "2", '"', "\\", "+", "9", "&", "3", "-", ";", "4", "!", "?", "5", "#", "$", "7"]
        self.alpha = [ "m", "t", "u", "v", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "n", "o", "p", "q", "r", "s", "w", "x", "y", "z"]
        self.characters = self.symbols_and_numbers + self.alpha
        self.key_length = choice([16, 17, 18, 19, 20, 21, 22, 23])
        self.fernet_key = Fernet.generate_key()
        self.fernet = Fernet(self.fernet_key)
        self.user = getuser()
        self.version_info = "SecureVault 1.0. It is a tool that allows you to generate secure keys."

    def generate_key(self):
        self.generated_key = ""
        for _ in range(self.key_length):
            char = choice(self.characters)
            if char not in self.symbols_and_numbers and choice(range(10)) in [0, 3, 4, 6, 7]:
                self.generated_key += char.upper()
            else:
                self.generated_key += char
        return self.generated_key

    def read_key(self):
        for _ in range(2):
            key_name = input("Enter the name of your password: ").strip()
            key_path = f"/home/{self.user}/KeySafe/.VaultSecret/{key_name}"
            with open(f"/home/{self.user}/KeySafe/.VaultSecret/.key", 'r') as key_file:
                stored_hash = key_file.read()

            user_password = getpass("Enter your password: ").strip()
            hashed_password = sha3_512(user_password.encode()).hexdigest()
            if stored_hash == hashed_password:
                with open(key_path, 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(user_password.encode())
                    user_password = ""
                    decrypted_key = fernet.decrypt(encrypted_key)
                    fernet = ""
                    print(f"Your password is => {decrypted_key.decode()}")
                    decrypted_key = ""
                    break
            else:
                print("Incorrect password!")

    def store_unique_key(self):
        key_path = f"/home/{self.user}/KeySafe/.VaultSecret/.key"
        if not path.isfile(key_path):
            with open(key_path, 'w') as key_file:
                hashed_key = sha3_512(self.fernet_key).hexdigest()
                key_file.write(hashed_key)
                system(f"chmod 600 {key_path}")
                print(f"Your password is => {self.fernet_key.decode()}")
                self.fernet_key = ""
        else:
            print("The password already exists!")

    def save_key(self):
        confirm = input("Would you like to save the password (y/n): ").strip().lower()
        if confirm == "y":
            for _ in range(2):
                key_name = input("Enter the name of the file that will store your password: ").strip()
                key_path = f"/home/{self.user}/KeySafe/.VaultSecret/{key_name}"
                if not path.isfile(key_path):
                    with open(f"/home/{self.user}/KeySafe/.VaultSecret/.key", 'r') as key_file:
                        stored_hash = key_file.read()

                    user_password = getpass("Enter your password: ").strip()
                    hashed_password = sha3_512(user_password.encode()).hexdigest()
                    if stored_hash == hashed_password:
                        with open(key_path, 'wb') as key_file:
                            fernet = Fernet(user_password.encode())
                            user_password = ""
                            encrypted_key = fernet.encrypt(self.generated_key.encode())
                            fernet = ""
                            key_file.write(encrypted_key)
                            system(f"chmod 600 {key_path}")
                            print("Your password has been saved successfully!")
                            break
                    else:
                        print("Incorrect password!")
                else:
                    print("Password name already exists!")
    def list_password(self):
            self.listen = listdir(f"/home/{self.user}/KeySafe/.VaultSecret/") 
            for x in self.listen: 
                print(x)
    

    def delete(self):
          for _ in range(2):
            key_name = input("Enter the name of your password: ").strip()
            key_path = f"/home/{self.user}/KeySafe/.VaultSecret/{key_name}"
            with open(f"/home/{self.user}/KeySafe/.VaultSecret/.key", 'r') as key_file:
                stored_hash = key_file.read()

            user_password = getpass("Enter your password: ").strip()
            hashed_password = sha3_512(user_password.encode()).hexdigest()
            user_password = ""
            if stored_hash == hashed_password:
               remove(key_path)
               print("Your password has been successfully deleted!")
               break

            else:
                print("Incorrect password!")

    def main(self):
        try:
            system(f"chmod 700 /home/{self.user}/KeySafe/sv.py")
            secret_dir = f"/home/{self.user}/KeySafe/.VaultSecret"
            if not path.isdir(secret_dir):
                mkdir(secret_dir)
                system(f"chmod 700 {secret_dir}")

            if "-g" in argv:
                print(f"Key-Safe => {self.generate_key()}")
                self.save_key()
            elif "-V" in argv:
                print(self.version_info)
            elif "-u" in argv:
                self.store_unique_key()
            elif "-r" in argv:
                self.read_key()
            elif "-d" in argv:
                self.delete()
            elif "-l" in argv:
                self.list_password()
            elif "-h" in argv or "--help" in argv:
                print("""
SecureVault 1.0. It is a tool that allows you to generate secure keys.
Usage:
    python3 sv.py -g  generate a secure key
    python3 sv.py -V  print version info and exit
    python3 sv.py -r  read a stored password by its custom name
    python3 sv.py -u  generate a unique key
    python3 sv.py -d  delete secure key
    python3 sv.py -l  list your stored passwords
Help Menu:
    -h  --help  print this help message and exit
                """)
            else:
                print("SecureVault: invalid arguments. Use -g to generate a secure key. Try --help for more information.")
        except (KeyboardInterrupt,EOFError):
            print()
            
        except FileNotFoundError as e:
            print(f"Path or file does not exist => {e}")
            

        except:
            print("Invalid or corrupt password!")

if __name__ == "__main__":
    vault = SecureVault()
    vault.main()
