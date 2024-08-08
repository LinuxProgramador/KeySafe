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
        self.malicious_symbols = list("';|&}{][><)($@:`,°")
        self.malicios_simbols_and_comands =["echo","rm","cat","exec","wget","curl","&&","||","\"","\\"]
        self.sanitize_entry = self.malicios_simbols_and_comands + self.malicious_symbols
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help']
        self.key_path = f"/home/{self.user}/KeySafe/.VaultSecret"
        self.sv_path = f"/home/{self.user}/KeySafe"

    def generate_key(self):
        
        self.generated_key = ""
        for _ in range(self.key_length):
            char = choice(self.characters)
            if char not in self.symbols_and_numbers and choice(range(10)) in [0, 3, 4, 6, 7]:
                self.generated_key += char.upper()
            else:
                self.generated_key += char
        return self.generated_key

    def is_sanitized(self,entry):
      for char in entry:
         if char in self.sanitize_entry:
            exit(2)
      return True

    
    def hashing_password_input(self):
            self.frequent_user_entry = getpass("Enter your password: ").strip()
            if self.is_sanitized(self.frequent_user_entry) and len(self.frequent_user_entry) <= 45:
               hashed_password = sha3_512(self.frequent_user_entry.encode()).hexdigest()
            else:
                exit(2)
            return hashed_password

    def read_key(self):
        
        for _ in range(2):
          key_name = input("Enter the name of your password: ").strip()
          if self.is_sanitized(key_name) and len(key_name) <= 20:
             with open(path.join(self.key_path,".key"), 'r') as key_file:
                stored_hash = key_file.read()

            
             if stored_hash == self.hashing_password_input():
                with open(path.join(self.key_path,key_name), 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(self.frequent_user_entry.encode())
                    self.frequent_user_entry = ""
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
        
        
        if not path.isfile(path.join(self.key_path,".key")):
            with open(path.join(self.key_path,".key"), 'w') as key_file:
                hashed_key = sha3_512(self.fernet_key).hexdigest()
                key_file.write(hashed_key)
                chmod(path.join(self.key_path,".key"), 0o600)
                print(f"Your password is => {self.fernet_key.decode()}")
                self.fernet_key = ""
        else:
            print("The password already exists!")

    

    def save_key(self):
        
      confirm = input("Would you like to save the password (y/n): ").strip().lower()
      if self.is_sanitized(confirm) and len(confirm) < 2:
        if confirm == "y":
            for _ in range(2):
              key_name = input("Enter the name of the file that will store your password: ").strip()
              if self.is_sanitized(key_name) and len(key_name) <= 20:
                 if not path.isfile(path.join(self.key_path,key_name)):
                    with open(path.join(self.key_path,".key"), 'r') as key_file:
                        stored_hash = key_file.read()

                    
                    if stored_hash == self.hashing_password_input():
                        with open(path.join(self.key_path,key_name), 'wb') as key_file:
                            fernet = Fernet(self.frequent_user_entry.encode())
                            self.frequent_user_entry = ""
                            encrypted_key = fernet.encrypt(self.generated_key.encode())
                            self.generated_key = ""
                            fernet = ""
                            key_file.write(encrypted_key)
                            chmod(path.join(self.key_path,key_name), 0o600)
                            print("Your password has been saved successfully!")
                            break
                    else:
                        print("Incorrect password!")
                 else:
                    print("Password name already exists!")
              else:
                 exit(2)
      else:
          exit(2)
    
    def list_password(self):
        
            self.listen = listdir(self.key_path) 
            for x in self.listen: 
                if x != ".key":
                   print(x)
    

    def delete(self):
        
          for _ in range(2):
           key_name = input("Enter the name of your password: ").strip()
           if self.is_sanitized(key_name) and len(key_name) <= 20:
             with open(path.join(self.key_path,".key"), 'r') as key_file:
                stored_hash = key_file.read()

            
             if stored_hash == self.hashing_password_input():
               self.frequent_user_entry = ""
               if key_name != ".key":
                 if (stat(path.join(self.key_path,key_name)).st_mode & 0o777) == 0o600:
                   remove(path.join(self.key_path,key_name))
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
            chmod(path.join(self.sv_path,"sv.py"), 0o700)
            if not path.isdir(self.key_path):
                mkdir(self.key_path)
                chmod(self.key_path, 0o700)
                
            if len(argv) >= 2 and not argv[1] in self.options:
                if not self.is_sanitized(argv[1) or len(argv) > 2:
                    exit(2)
            elif self.options[2] in argv:
                print(f"Key-Safe => {self.generate_key()}")
                self.save_key()
            elif self.options[3] in argv:
                print(self.version_info)
            elif self.options[5] in argv:
                self.store_unique_key()
            elif self.options[1] in argv:
                self.read_key()
            elif self.options[0] in argv:
                self.delete()
            elif self.options[4] in argv:
                self.list_password()
            elif self.options[6] in argv or self.options[7] in argv:
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
            print("Possible malicious symbol lockout, or password corruption failure!")
        
           

if __name__ == "__main__":
    vault = SecureVault()
    vault.main()
