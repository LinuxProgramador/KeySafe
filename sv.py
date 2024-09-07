#!/usr/bin/python3

#Tool to generate secure keys and store them safely on Linux distros

from secrets import choice
from sys import argv, exit
from os import chmod, path, mkdir, remove, listdir, stat, urandom
from cryptography.fernet import Fernet, InvalidToken
from bcrypt import checkpw, hashpw, gensalt 
from getpass import getpass, getuser
from string import ascii_lowercase, digits, ascii_uppercase
from subprocess import run, CalledProcessError
from signal import signal, SIGTSTP
from shutil import copy
from datetime import datetime


class SecureVault:
    '''
    SecureVault class provides functionalities to generate, store, and manage cryptographic keys.
    '''
    def __init__(self):
        '''
        Initializes the SecureVault instance with default values.
        '''
        self.data_overwrite = urandom(2048)
        self.characters = ascii_lowercase + digits + '@/*_"\',\\+&-;!?#$' + ascii_uppercase
        self.malicious_symbols = list("/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°")
        self.malicios_symbols_and_commands = ["ping","ss","id","whoami", "groups","disown",
        "nohup","fg","bg","more","dir","ps","ls","cd","nano","vim","echo","cat","exec","wget",
        "curl","host","df","system","..","&&","||","\"","\\"]                                        
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help','-b']
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
        key_length = choice(range(15 ,65))
        generated_key = ""
        query_longitude = int(getpass("Set key length (15/64) or press zero for default: "))
        if query_longitude:
         if len(str(query_longitude)) <= 3:
          if query_longitude >= 15 and query_longitude <= 64:
             key_length = query_longitude
          else:
             print("You entered a number outside the allowed range, the default value will be set!")
         else:
            print("Possible block due to length exceeded!")
            exit(1)
        for _ in range(key_length):
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
      elif len(entry) >= 44:
        for rm_indices in list("/+_-="):
           if rm_indices in self.malicious_symbols:
              self.malicious_symbols.remove(rm_indices)
      for char in entry:
         if char in self.malicious_symbols:
            print("Possible blocking due to malicious symbol!")
            exit(1)
      return True

    
    def password_entry_validation(self):
            '''
            Allows you to enter a key to validate with the stored password hash 
            '''
            frequent_user_entry = getpass("Enter your password: ").strip().replace(" ","")
            if self.is_sanitized(frequent_user_entry) and len(frequent_user_entry) <= 45:
               return frequent_user_entry.encode()
            else:
                print("Possible block due to length exceeded!")
                exit(1)

    
    def read_key_local(self):
         '''
         read the hash of the key stored in the .key file 
         '''
         with open(path.join(self.key_path,".key"), 'rb') as key_file:
                stored_hash = key_file.read()
                return stored_hash
             
             
    def name_input(self):
         '''  
         Function to set the name of the file where the password is.
         '''                                                                                   
         key_name = input("Enter the name of your password: ").strip().replace(" ","")         
         if self.is_sanitized(key_name) and len(key_name) <= 40:
             return key_name
         else:
             print("Possible block due to length exceeded!")
             exit(1)   
             

    def read_key(self):
        '''
        Reads a stored key by prompting the user for its name and verifying the password.
        '''
        for _ in range(2):
             key_name = self.name_input()
             temp_entry = self.password_entry_validation()
             if checkpw(temp_entry, self.read_key_local()):
              if key_name != ".key":
                with open(path.join(self.key_path,key_name), 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(temp_entry)
                    temp_entry = self.data_overwrite
                    decrypted_key = fernet.decrypt(encrypted_key)
                    fernet = self.data_overwrite
                    print(f"Your password is => {decrypted_key.decode()}")
                    decrypted_key = self.data_overwrite
                    break
              else:
                  print("Can't read the unique key!")
                  temp_entry = self.data_overwrite
             else:
                print("Incorrect password!")
        return
    

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
                fernet_key = self.data_overwrite
        else:
            print("The password already exists!")
        return
    

    def save_key(self,temp_encrypt,temp_fernet_key):
      '''
      Saves a generated key to a specified file, after verifying the password.
      '''  
      confirm = input("Would you like to save the password (y/n): ").strip().lower()
      if self.is_sanitized(confirm) and len(confirm) < 2:
        if confirm == "y":
            for _ in range(2):
                 key_name = self.name_input()
                 if not path.isfile(path.join(self.key_path,key_name)):
                    temp_entry = self.password_entry_validation()
                    if checkpw(temp_entry, self.read_key_local()):
                        with open(path.join(self.key_path,key_name), 'wb') as key_file:
                            fernet = Fernet(temp_entry)
                            temp_entry = self.data_overwrite
                            temp_encrypt = temp_fernet_key.decrypt(temp_encrypt)
                            encrypted_key = fernet.encrypt(temp_encrypt)
                            temp_encrypt = self.data_overwrite
                            temp_fernet_key = self.data_overwrite
                            fernet = self.data_overwrite
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
      return
    
    def list_password(self):
            '''
            Lists all stored passwords except the .key file.
            '''
            listen = listdir(self.key_path) 
            for x in listen: 
                if x != ".key":
                   print(x)
            

    def delete(self):
          '''
          Deletes a specified key file after verifying the password.
          '''
          for _ in range(2):
             key_name = self.name_input()
             if not path.isfile(path.join(self.key_path,key_name)):
                 print("Error, please enter a valid name!")
                 exit(1)
             temp_entry = self.password_entry_validation()
             if checkpw(temp_entry, self.read_key_local()):
               temp_entry = self.data_overwrite
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
            return 

    
    def backup(self):
         '''
         Function that allows you to create a backup locally
         '''
         for _ in range(2):
          temp_entry = self.password_entry_validation()
          if checkpw(temp_entry, self.read_key_local()):
            temp_entry = self.data_overwrite
            files = listdir(self.key_path)
            path_backup = f"/home/{self.user}/.BacKupSV"
            if not path.isdir(path_backup):
                  mkdir(path_backup)
                  chmod(path_backup, 0o700)
            for file in files:
              if not path.isfile(path.join(path_backup,file + " " + str(datetime.now()))):
                copy(path.join(self.key_path,file),path.join(path_backup,file + " " + str(datetime.now())))
            print(f"The backup was created successfully in => {path_backup}")
            break
          else:
             print("Incorrect password!")
         return     

    

    def show_help(self):
        '''
        When the function is called, it prints the help menu.
        '''
        print("SecureVault 1.0. It is a tool that allows you to generate secure keys.")
        print("""
Usage:
    python3 sv.py -g  generate a secure key
    python3 sv.py -V  print version info and exit
    python3 sv.py -r  read a stored password by its custom name
    python3 sv.py -u  generate a unique key
    python3 sv.py -d  delete secure key
    python3 sv.py -l  list your stored passwords
    python3 sv.py -b  create a backup locally
Help Menu:
    -h  --help  print this help message and exit
                """)
        
        

    def temporary_key_encryption(self,temp_encrypt):
        '''
        Function that allows the encoding of the key generated by the generate_key method
        '''
        key = Fernet.generate_key()
        temp_fernet_key = Fernet(key)
        key = self.data_overwrite
        temp_encrypt = temp_fernet_key.encrypt(temp_encrypt.encode())
        self.save_key(temp_encrypt,temp_fernet_key)
        temp_fernet_key = self.data_overwrite                                       
        return
        

    def main(self):
        '''
        Main function, which will perform tasks based on the arguments given by the user.
        '''
        try:
            signal(SIGTSTP, self.handle_tstp_signal)
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
                temp_encrypt = self.generate_key()
                print(f"Key-Safe => {temp_encrypt}")
                self.temporary_key_encryption(temp_encrypt)
                temp_encrypt = self.data_overwrite
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
            elif self.options[8] in argv:
                 self.backup()
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
            print("Error, a directory has been detected!")
        except TypeError:  
            print("An error occurred while creating the backup!")
        except OSError:
           print("An error has occurred in the system that prevents the correct execution of the given function!")
        return
              
if __name__ == "__main__":
   try:
    process = run(['/usr/bin/ps', 'aux'], text=True, check=True, capture_output=True)
    output = [line for line in process.stdout.splitlines() if 'sv.py' in line]
    if not any('S+' in line for line in output):
       exit(1)
    elif getuser() == 'root':
       print("Access denied to root user!")
       exit(1)
    else:
       vault = SecureVault()
       vault.main()
           
   except CalledProcessError:
      print("Error running ps command!")
      

__name__="SecureVault"
__version__="1.0"
__author__="WhiteHack"
__maintainer__="WhiteHack"
__license__="GPL"
__status__="stable"
