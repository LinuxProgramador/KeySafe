#!/usr/bin/python3

#Tool to generate secure keys and store them safely on Linux distros

from secrets import choice
from sys import argv
from os import chmod, path, mkdir, remove, listdir, stat
from cryptography.fernet import Fernet
from bcrypt import checkpw, hashpw, gensalt 
from getpass import getpass, getuser


class SecureVault:
    
    '''
    SecureVault class provides functionalities to generate, store, and manage cryptographic keys.
    '''
    def __init__(self):
        '''
        Initializes the SecureVault instance with default values and generates a Fernet key.
        '''
        
        self.symbols_and_numbers = ["@", "1", "/", "*", "8", "_", "6", "0", "'", "2", '"', "\\", "+", "9", "&", "3", "-", ";", "4", "!", "?", "5", "#", "$", "7"]
        self.alpha = list("abcdefghijklmnopqrstuvwxyz")
        self.characters = self.symbols_and_numbers + self.alpha
        self.key_length = choice(range(15 ,65))
        self.fernet_key = Fernet.generate_key()
        self.user = getuser()
        self.version_info = "SecureVault 1.0. It is a tool that allows you to generate secure keys."
        self.malicious_symbols = list("';|&}!{][*>%<)($@:`,°")
        self.malicios_simbols_and_comands =["umount","mount","ls","cd","nano","vim","chown","chmod","mkfs","dd","..","echo","rm","cat","exec","wget","curl","&&","||","\"","\\"]
        self.sanitize_entry = self.malicios_simbols_and_comands + self.malicious_symbols
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help']
        self.key_path = f"/home/{self.user}/KeySafe/.VaultSecret"
        self.sv_path = f"/home/{self.user}/KeySafe"

    def generate_key(self):
        '''
        Generates a secure cryptographic key with a user-defined or default length.
        '''
        
        self.generated_key = ""
        query_longitude = int(getpass("Set key length (15/64) or press zero for default: "))
        if bool(query_longitude) == True:
         if len(str(query_longitude)) <= 3:
          if query_longitude >= 15 and query_longitude <= 64:
             self.key_length = query_longitude
          else:
             print("You entered a number outside the allowed range, the default value will be set!")

         else:
            raise Exception
            
        for _ in range(self.key_length):
            char = choice(self.characters)
            if char not in self.symbols_and_numbers and choice(range(10)) in [0, 3, 4, 6, 7]:
                self.generated_key += char.upper()
            else:
                self.generated_key += char
        return self.generated_key

    def is_sanitized(self,entry):
      '''
      Checks if the provided entry contains any malicious symbols or commands.
      '''
      if entry in self.sanitize_entry:
              raise Exception
      for char in entry:
         if char in self.sanitize_entry:
            raise Exception
      return True

    
    def hashing_password_input(self):
            self.frequent_user_entry = getpass("Enter your password: ").strip().replace(" ","")
            if self.is_sanitized(self.frequent_user_entry) and len(self.frequent_user_entry) <= 45:
               return self.frequent_user_entry.encode()
            else:
                raise Exception
            

    def read_key(self):
        
        for _ in range(2):
          key_name = input("Enter the name of your password: ").strip().replace(" ","")
          if self.is_sanitized(key_name) and len(key_name) <= 40:
             with open(path.join(self.key_path,".key"), 'rb') as key_file:
                stored_hash = key_file.read()

            
             if checkpw(self.hashing_password_input(), stored_hash):
              if key_name != ".key":
                with open(path.join(self.key_path,key_name), 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(self.frequent_user_entry.encode())
                    self.frequent_user_entry = None
                    decrypted_key = fernet.decrypt(encrypted_key)
                    fernet = None
                    print(f"Your password is => {decrypted_key.decode()}")
                    decrypted_key = None
                    break
              else:
                  print("Can't read the unique key!")
             else:
                print("Incorrect password!")
          else:
              raise Exception

    

    def store_unique_key(self):
        
        
        if not path.isfile(path.join(self.key_path,".key")):
            with open(path.join(self.key_path,".key"), 'wb') as key_file:
                hashed_key = hashpw(self.fernet_key,gensalt())
                key_file.write(hashed_key)
                chmod(path.join(self.key_path,".key"), 0o600)
                print(f"Your password is => {self.fernet_key.decode()}")
                self.fernet_key = None
        else:
            print("The password already exists!")

    

    def save_key(self):
        
      confirm = input("Would you like to save the password (y/n): ").strip().lower()
      if self.is_sanitized(confirm) and len(confirm) < 2:
        if confirm == "y":
            for _ in range(2):
              key_name = input("Enter the name of the file that will store your password: ").strip().replace(" ","")
              if self.is_sanitized(key_name) and len(key_name) <= 40:
                 if not path.isfile(path.join(self.key_path,key_name)):
                    with open(path.join(self.key_path,".key"), 'rb') as key_file:
                        stored_hash = key_file.read()

                    
                    if checkpw(self.hashing_password_input(), stored_hash):
                        with open(path.join(self.key_path,key_name), 'wb') as key_file:
                            fernet = Fernet(self.frequent_user_entry.encode())
                            self.frequent_user_entry = None
                            encrypted_key = fernet.encrypt(self.generated_key.encode())
                            self.generated_key = None
                            fernet = None
                            key_file.write(encrypted_key)
                            chmod(path.join(self.key_path,key_name), 0o600)
                            print("Your password has been saved successfully!")
                            break
                    else:
                        print("Incorrect password!")
                 else:
                    print("Password name already exists!")
              else:
                 raise Exception
      else:
          raise Exception
    
    def list_password(self):
        
            self.listen = listdir(self.key_path) 
            for x in self.listen: 
                if x != ".key":
                   print(x)
    

    def delete(self):
        
          for _ in range(2):
           key_name = input("Enter the name of your password: ").strip().replace(" ","")
           if self.is_sanitized(key_name) and len(key_name) <= 40:
             with open(path.join(self.key_path,".key"), 'rb') as key_file:
                stored_hash = key_file.read()

            
             if checkpw(self.hashing_password_input(), stored_hash):
               self.frequent_user_entry = None
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
               raise Exception
                
                

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
                if not self.is_sanitized(argv[1]) or len(argv) > 2 or len(argv[1]) > 7:
                    raise Exception
                else:
                     print("SecureVault: invalid arguments. Use -g to generate a secure key. Try --help for more information.")
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
            
        except ValueError:
            print("You did not enter any integer!")   
            
        except:
            print("Possible malicious symbol lock error, allowed length exceeded, or password corruption!")
        
           

if __name__ == "__main__":
    if getuser() == 'root':
          print("Access denied to root user!")
          exit(1)
    else:
          vault = SecureVault()
          vault.main()


__name__="SecureVault"
__version__="1.0"
__maintainer__="WhiteHack"
__license__="GPL"

