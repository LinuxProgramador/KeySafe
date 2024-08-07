#!/usr/bin/python3

# SecureVault 1.0
# Author: WhiteHack

from secrets import choice
from sys import argv, exit
from os import chmod, path, mkdir, remove, listdir, stat
from cryptography.fernet import Fernet
from hashlib import sha3_512
from getpass import getpass, getuser


class SecureVault:
    

    def __init__(self):
        
        self.symbols_and_numbers = ["@", "1", "/", "*", "8", "_", "6", "0", "'", "2", '"', "\\", "+", "9", "&", "3", "-", ";", "4", "!", "?", "5", "#", "$", "7"]
        self.alpha = list("abcdefghijklmnopqrstuvwxyz")
        self.characters = self.symbols_and_numbers + self.alpha
        self.key_length = choice(range(16 ,29))
        self.fernet_key = Fernet.generate_key()
        self.user = getuser()
        self.version_info = "SecureVault 1.0. It is a tool that allows you to generate secure keys."
        self.malicious_symbols = list("';|&}{][><)($@:`,-°")
        self.malicios_simbols_and_comands =["echo","rm","cat","exec","wget","curl","&&","||","--","\"","\\"]
        self.sanitize_entry = self.malicios_simbols_and_comands + self.malicious_symbols
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help']
        

    def generate_key(self):
        
        self.generated_key = ""
        for _ in range(self.key_length):
            char = choice(self.characters)
            if char not in self.symbols_and_numbers and choice(range(10)) in [0, 3, 4, 6, 7]:
                self.generated_key += char.upper()
            else:
                self.generated_key += char
        return self.generated_key

    
    def hashing_password_input(self):
            self.user_password = getpass("Enter your password: ").strip()
            if not self.user_password in self.sanitize_entry and len(self.user_password) <= 79:
               hashed_password = sha3_512(self.user_password.encode()).hexdigest()
            else:
                exit(2)
            return hashed_password

    def read_key(self):
        
        for _ in range(2):
          key_name = input("Enter the name of your password: ").strip()
          if not key_name in self.sanitize_entry and len(key_name) <= 20:
             key_path = f"/home/{self.user}/KeySafe/.VaultSecret/{key_name}"
             with open(f"/home/{self.user}/KeySafe/.VaultSecret/.key", 'r') as key_file:
                stored_hash = key_file.read()

            
             if stored_hash == self.hashing_password_input():
                with open(key_path, 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(self.user_password.encode())
                    self.user_password = ""
                    decrypted_key = fernet.decrypt(encrypted_key)
                    fernet = ""
                    print(f"Your password is => {decrypted_key.decode()}")
                    decrypted_key = ""
                    break
             else:
                print("Incorrect password!")
          else:
              exit(2)

    

    def store_unique_key(self):
        
        key_path = f"/home/{self.user}/KeySafe/.VaultSecret/.key"
        if not path.isfile(key_path):
            with open(key_path, 'w') as key_file:
                hashed_key = sha3_512(self.fernet_key).hexdigest()
                key_file.write(hashed_key)
                chmod(key_path, 0o600)
                print(f"Your password is => {self.fernet_key.decode()}")
                self.fernet_key = ""
        else:
            print("The password already exists!")

    

    def save_key(self):
        
        confirm = input("Would you like to save the password (y/n): ").strip().lower()
        if confirm == "y":
            for _ in range(2):
              key_name = input("Enter the name of the file that will store your password: ").strip()
              if not key_name in self.sanitize_entry and len(key_name) <= 20:
                 key_path = f"/home/{self.user}/KeySafe/.VaultSecret/{key_name}"
                 if not path.isfile(key_path):
                    with open(f"/home/{self.user}/KeySafe/.VaultSecret/.key", 'r') as key_file:
                        stored_hash = key_file.read()

                    
                    if stored_hash == self.hashing_password_input():
                        with open(key_path, 'wb') as key_file:
                            fernet = Fernet(self.user_password.encode())
                            self.user_password = ""
                            encrypted_key = fernet.encrypt(self.generated_key.encode())
                            self.generated_key = ""
                            fernet = ""
                            key_file.write(encrypted_key)
                            chmod(key_path, 0o600)
                            print("Your password has been saved successfully!")
                            break
                    else:
                        print("Incorrect password!")
                 else:
                    print("Password name already exists!")
              else:
                 exit(2)

    
    def list_password(self):
        
            self.listen = listdir(f"/home/{self.user}/KeySafe/.VaultSecret") 
            for x in self.listen: 
                if x != ".key":
                   print(x)
    

    def delete(self):
        
          for _ in range(2):
           key_name = input("Enter the name of your password: ").strip()
           if not key_name in self.sanitize_entry and len(key_name) <= 20:
             key_path = f"/home/{self.user}/KeySafe/.VaultSecret/{key_name}"
             with open(f"/home/{self.user}/KeySafe/.VaultSecret/.key", 'r') as key_file:
                stored_hash = key_file.read()

            
             if stored_hash == self.hashing_password_input():
               self.user_password = ""
               if key_name != ".key":
                 if (stat(key_path).st_mode & 0o777) == 0o600:
                   remove(key_path)
                   print("The file has been successfully deleted!")
                   break
                 else:
                     print("The permissions were altered, for security the file will not be deleted!")

               else:
                   print("The unique key cannot be deleted!")
             else:
                print("Incorrect password!")
           else:
               exit(2)
                
                

    def show_help(self):
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
        

    def main(self):
        
        try:
            chmod(f"/home/{self.user}/KeySafe/sv.py", 0o700)
            secret_dir = f"/home/{self.user}/KeySafe/.VaultSecret"
            if not path.isdir(secret_dir):
                mkdir(secret_dir)
                chmod(secret_dir, 0o700)
                
            if len(argv) >= 2 and not argv[1] in self.options:
                if argv[1] in self.sanitize_entry:
                    exit(2)
            elif "-g" in argv:
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
                self.show_help()
            else:
                print("SecureVault: invalid arguments. Use -g to generate a secure key. Try --help for more information.")

        
        except (KeyboardInterrupt,EOFError):
            print("\nOperation canceled by user!")
            
        except FileNotFoundError as e:
            print(f"Path or file does not exist => {e}")

        except PermissionError as p:
            print(f"Permissions error on the file or directory => {p}")
            
        except:
            print("Possible error, malicious symbol lockout, or password corruption failure!")
        
           

if __name__ == "__main__":
    vault = SecureVault()
    vault.main()
