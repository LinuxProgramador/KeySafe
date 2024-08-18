#!/usr/bin/python3

#Tool to generate secure keys and store them safely on Linux distros

from secrets import choice
from sys import argv, exit
from os import chmod, path, mkdir, remove, listdir, stat
from cryptography.fernet import Fernet, InvalidToken
from bcrypt import checkpw, hashpw, gensalt 
from getpass import getpass, getuser
from string import ascii_lowercase, digits, ascii_uppercase
import subprocess, signal

class SecureVault:
    '''
    SecureVault class provides functionalities to generate, store, and manage cryptographic keys.
    '''
    def __init__(self):
        '''
        Initializes the SecureVault instance with default values and generates a Fernet key.
        '''
        self.characters = ascii_lowercase + digits + '@/*_"\',\\+&-;!?#$' + ascii_uppercase
        self.key_length = choice(range(15 ,65))
        self.malicious_symbols = list("'~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°")
        self.malicios_symbols_and_commands =["umount","mount","ls","cd","nano","vim","chown","chmod","mkfs","dd","..","echo","rm","cat","exec","wget","curl","&&","||","\"","\\"]
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help']
        self.user = getuser()
        self.key_path = f"/home/{self.user}/KeySafe/.VaultSecret"
        self.sv_path = f"/home/{self.user}/KeySafe"

    def handle_tstp_signal(self,signum,frame):
       '''
       Function that allows me to catch the signal produced by the ctrl_z key
       '''
       print('')
       exit(1)

    def generate_key(self):
        '''
        Generates a secure cryptographic key with a user-defined or default length.
        '''
        generated_key = ""
        query_longitude = int(getpass("Set key length (15/64) or press zero for default: "))
        if query_longitude:
         if len(str(query_longitude)) <= 3:
          if query_longitude >= 15 and query_longitude <= 64:
             self.key_length = query_longitude
          else:
             print("You entered a number outside the allowed range, the default value will be set!")
         else:
            print("Possible block due to length exceeded!")
            exit(1)
        for _ in range(self.key_length):
            char = choice(list(self.characters))
            generated_key += char
        return generated_key

    def is_sanitized(self,entry):
      '''
      Checks if the provided entry contains any malicious symbols or commands.
      '''
      sanitize_entry = self.malicious_symbols + self.malicios_symbols_and_commands
      if entry in sanitize_entry:
            print("Possible blocking due to malicious symbol!")
            exit(1)
      for char in entry:
         if char in sanitize_entry:
            print("Possible blocking due to malicious symbol!")
            exit(1)
      return True

    
    def hashing_password_input(self):
            '''
            Hashes the user's password input for validation purposes.
            '''
            frequent_user_entry = getpass("Enter your password: ").strip().replace(" ","")
            if self.is_sanitized(frequent_user_entry) and len(frequent_user_entry) <= 45:
               return frequent_user_entry.encode()
            else:
                print("Possible block due to length exceeded!")
                exit(1)
            

    def read_key(self):
        '''
        Reads a stored key by prompting the user for its name and verifying the password.
        '''
        for _ in range(2):
          key_name = input("Enter the name of your password: ").strip().replace(" ","")
          if self.is_sanitized(key_name) and len(key_name) <= 40:
             with open(path.join(self.key_path,".key"), 'rb') as key_file:
                stored_hash = key_file.read()
             temp_entry = self.hashing_password_input()
             if checkpw(temp_entry, stored_hash):
              if key_name != ".key":
                with open(path.join(self.key_path,key_name), 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(temp_entry)
                    del(temp_entry)
                    decrypted_key = fernet.decrypt(encrypted_key)
                    del(fernet)
                    print(f"Your password is => {decrypted_key.decode()}")
                    del(decrypted_key)
                    break
              else:
                  print("Can't read the unique key!")
                  del(temp_entry)
             else:
                print("Incorrect password!")
          else:
              print("Possible block due to length exceeded!")
              exit(1)

    

    def store_unique_key(self):
        '''
        Stores a unique key by creating a .key file if it does not already exist.
        '''
        if not path.isfile(path.join(self.key_path,".key")):
            fernet_key = Fernet.generate_key()
            with open(path.join(self.key_path,".key"), 'wb') as key_file:
                hashed_key = hashpw(fernet_key,gensalt())
                key_file.write(hashed_key)
                chmod(path.join(self.key_path,".key"), 0o600)
                print(f"Your password is => {fernet_key.decode()}")
                del(fernet_key)
        else:
            print("The password already exists!")

    

    def save_key(self,temp_encrypt,fernet_key_generate):
      '''
      Saves a generated key to a specified file, after verifying the password.
      '''  
      confirm = input("Would you like to save the password (y/n): ").strip().lower()
      if self.is_sanitized(confirm) and len(confirm) < 2:
        if confirm == "y":
            for _ in range(2):
              key_name = input("Enter the name of the file that will store your password: ").strip().replace(" ","")
              if self.is_sanitized(key_name) and len(key_name) <= 40:
                 if not path.isfile(path.join(self.key_path,key_name)):
                    with open(path.join(self.key_path,".key"), 'rb') as key_file:
                        stored_hash = key_file.read()
                    temp_entry = self.hashing_password_input()
                    if checkpw(temp_entry, stored_hash):
                        with open(path.join(self.key_path,key_name), 'wb') as key_file:
                            fernet = Fernet(temp_entry)
                            del(temp_entry)
                            temp_encrypt = fernet_key_generate.decrypt(temp_encrypt)
                            encrypted_key = fernet.encrypt(temp_encrypt)
                            del(temp_encrypt)
                            del(fernet_key_generate)
                            del(fernet)
                            key_file.write(encrypted_key)
                            chmod(path.join(self.key_path,key_name), 0o600)
                            print("Your password has been saved successfully!")
                            break
                    else:
                        print("Incorrect password!")
                 else:
                    print("Password name already exists!")
              else:
                 print("Possible block due to length exceeded!")
                 exit(1)
      else:
          print("Possible block due to length exceeded!")
          exit(1)
      return
    
    def list_password(self):
            '''
            Lists all stored passwords except the .key file.
            '''
            self.listen = listdir(self.key_path) 
            for x in self.listen: 
                if x != ".key":
                   print(x)
    

    def delete(self):
          '''
          Deletes a specified key file after verifying the password.
          '''
          for _ in range(2):
           key_name = input("Enter the name of your password: ").strip().replace(" ","")
           if self.is_sanitized(key_name) and len(key_name) <= 40:
             with open(path.join(self.key_path,".key"), 'rb') as key_file:
                stored_hash = key_file.read()
             temp_entry = self.hashing_password_input()
             if checkpw(temp_entry, stored_hash):
               del(temp_entry)
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
               print("Possible block due to length exceeded!")
               exit(1)
                
                

    def show_help(self):
        '''
        When the function is called, it prints the help menu.
        '''
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
        '''
        Main function, which will perform tasks based on the arguments given by the user.
        '''
        try:
            chmod(path.join(self.sv_path,"sv.py"), 0o700)
            if not path.isdir(self.key_path):
                mkdir(self.key_path)
                chmod(self.key_path, 0o700)
            if len(argv) >= 2 and not argv[1] in self.options:
                if not self.is_sanitized(argv[1]) or len(argv) > 2 or len(argv[1]) > 7:
                    print("Possible block due to length exceeded!")
                    exit(1)
                else:
                     print("SecureVault: invalid arguments. Use -g to generate a secure key. Try --help for more information.")
            elif len(argv) >= 3:
                   print("Possible block due to length exceeded!")
                   exit(1)  
            elif self.options[2] in argv:
                key = Fernet.generate_key()
                fernet_key_generate = Fernet(key)
                del(key)
                temp_encrypt = self.generate_key()
                print(f"Key-Safe => {temp_encrypt}")
                temp_encrypt = fernet_key_generate.encrypt(temp_encrypt.encode())
                self.save_key(temp_encrypt,fernet_key_generate)
                del(temp_encrypt)
                del(fernet_key_generate)
            elif self.options[3] in argv:
                print("SecureVault 1.0. It is a tool that allows you to generate secure keys.")
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
        except ValueError:
            print("You did not enter any integer!")   
        except InvalidToken:
            print("Invalid Token Error!")
        except IsADirectoryError:
            print("Error, please enter a valid name!")
              
if __name__ == "__main__":
    process = subprocess.run('ps aux | grep  sv.py  | grep -v grep ', shell=True, text=True, capture_output=True)
    output = process.stdout
    if not 'S+' in output:
          exit(1)
    elif getuser() == 'root':
          print("Access denied to root user!")
          exit(1)
    else:
          vault = SecureVault()
          vault.main()


__name__="SecureVault"
__version__="1.0"
__maintainer__="WhiteHack"
__license__="GPL"

