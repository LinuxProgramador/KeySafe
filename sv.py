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
from pwd import getpwuid
from time import sleep


class SecureVault:
    '''
    SecureVault class provides functionalities to generate, store, and manage cryptographic keys.
    '''
    def __init__(self):
        '''
        Initializes the SecureVault instance with default values.
        '''
        self.characters = ascii_lowercase + digits + '@/*_"\',\\+&-;!?#$' + ascii_uppercase
        #gru These sets are customizable at the user's disposal to add more data (Recommended not to delete)
        self.malicious_symbols = set("/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°")
        self.malicious_symbols_and_commands = set(["ping","ss","id","whoami", "groups","disown",
        "nohup","fg","bg","more","dir","ps","ls","cd","nano","vim","echo","cat","exec","wget",
        "curl","host","df","system","..","&&","||","\"","\\"])                                       
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help','-b','-c']
        self.user = getuser()
        self.key_path = f"/home/{self.user}/KeySafe/.VaultSecret"
        self.sv_path = f"/home/{self.user}/KeySafe"

    def handle_tstp_signal(self,signum,frame):
       '''
       Function that allows me to catch the signal produced by the ctrl_z key.
       '''
       print("\nOperation not permitted!")
       exit(1)
        
        
    def immutable_data(self,data):
       '''
       (optional) set user keys to immutable added anti-delete security.
       '''
       """
       prompts the sudo password only once to cache it and prevent
       it from being requested repeatedly in subsequent commands during 
       the same session.
       """
       run(['/usr/bin/sudo','-S','/usr/bin/true'])
       try:
        list_attr_results = run(['/usr/bin/lsattr', path.join(self.key_path,data) ], text=True, check=True, capture_output=True)
        if any('-i' in line for line in list_attr_results.stdout.splitlines()):
           run(['/usr/bin/sudo', '/usr/bin/chattr', '-i', path.join(self.key_path,data) ], check=True, capture_output=True)
        elif not any('-i' in line for line in list_attr_results.stdout.splitlines()):
           run(['/usr/bin/sudo', '/usr/bin/chattr', '+i', path.join(self.key_path,data) ], check=True, capture_output=True)
       except CalledProcessError:
           print("An error occurred while applying immutability settings!")

    
    def data_overwrite(self):
        '''
        Allows overwriting variable values by a 2048-bit salt.
        '''
        return urandom(2048)
        
        
    def allowed_length_message(self):
        '''
        Shows the user that they have exceeded the allowed character length
        '''
        print("Possible block due to length exceeded!")
        exit(1)

    
    def generate_key(self):
        '''
        Generates a secure cryptographic key with a user-defined or default length.
        '''
        generated_key = ""
        query_longitude = int(getpass("Set key length (15/64) or press zero for default: "))
        key_length = choice(range(15 ,65))
        if query_longitude:
         if len(str(query_longitude)) <= 3:
          if query_longitude >= 15 and query_longitude <= 64:
             key_length = query_longitude
          else:
             print("You entered a number outside the allowed range, the default value will be set!")
         else:
            self.allowed_length_message()
        characters = list(self.characters)
        for _ in range(key_length):
            char = choice(characters)
            generated_key += char
        return generated_key

    def is_sanitized(self,entry):
      '''
      Checks if the provided entry contains any malicious symbols or commands.
      '''
      malicious_symbols_set = self.malicious_symbols | self.malicious_symbols_and_commands
      if path.isdir(entry) or path.isdir(path.join(self.key_path, entry)):
            print("Directory detected, operation denied!")
            exit(1)
      elif path.islink(entry) or path.islink(path.join(self.key_path, entry)):
            print("Symbolic link detected, operation denied!")
            exit(1)
      elif entry in malicious_symbols_set:
            print("Possible crash due to malicious symbol or command!")
            exit(1)
      #Disables certain malicious symbols so that the unique key can be entered in base64.
      elif len(entry) >= 44:
        sym = set([rm for rm in "/+_-=" if rm in self.malicious_symbols])
        self.malicious_symbols.difference_update(sym)
      for char in entry:
         if char in self.malicious_symbols:
            print("Possible crash due to malicious symbol or command!")
            exit(1)
      #It reactivates the malicious symbols after entering the user's password, thus maintaining security.
      self.malicious_symbols.update("/+_-=")
      return True

    
    def password_entry_validation(self):
            '''
            Allows you to enter a key to validate with the stored password hash.
            '''
            sleep(2)
            frequent_user_entry = getpass("Enter your unique password: ").strip().replace(" ","")
            if self.is_sanitized(frequent_user_entry) and len(frequent_user_entry) <= 45:
               return bytearray(frequent_user_entry,"utf-8")
            else:
                self.allowed_length_message()
                

    
    def read_key_local(self):
         '''
         read the hash of the key stored in the .key file.
         '''
         if self.is_sanitized(".key"):
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
             self.allowed_length_message()
             
             

    def read_key(self):
        '''
        Reads a stored key by prompting the user for its name and verifying the password.
        '''
        for _ in range(2):
             key_name = self.name_input()
             temp_entry = self.password_entry_validation()
             if checkpw(bytes(temp_entry), self.read_key_local()):
              if key_name != ".key":
                with open(path.join(self.key_path,key_name), 'rb') as key_file:
                    encrypted_key = key_file.read()
                    fernet = Fernet(bytes(temp_entry))
                    temp_entry = self.data_overwrite()
                    decrypted_key = bytearray(fernet.decrypt(encrypted_key))
                    fernet = self.data_overwrite()
                    print(f"Your password is => {decrypted_key.decode()}")
                    decrypted_key = self.data_overwrite()
                    break
              else:
                  print("Can't read the unique key!")
                  temp_entry = self.data_overwrite()
             else:
                print("Incorrect password!")
        return
    

    def store_unique_key(self):
        '''
        Stores a unique key by creating a .key file if it does not already exist.
        '''
        if not path.isfile(path.join(self.key_path,".key")):
            fernet_key = bytearray(Fernet.generate_key())
            with open(path.join(self.key_path,".key"), 'wb') as key_file:
                hashed_key = hashpw(bytes(fernet_key),gensalt())
                key_file.write(hashed_key)
                chmod(path.join(self.key_path,".key"), 0o600)
                print(f"Its unique key is => {fernet_key.decode()}")
                fernet_key = self.data_overwrite()
                self.immutable_data(".key")
        else:
            print("The password already exists!")
        return


    def auxiliary_save_key(self,key_name,temp_entry,temp_encrypt,temp_fernet_key):
      '''
      Helper function that divides the tasks of the save_key function
      '''
      with open(path.join(self.key_path,key_name), 'wb') as key_file:
            fernet = Fernet(bytes(temp_entry))
            temp_entry = self.data_overwrite()
            temp_encrypt = bytearray(temp_fernet_key.decrypt(temp_encrypt))
            encrypted_key = fernet.encrypt(bytes(temp_encrypt))
            temp_encrypt = self.data_overwrite()
            temp_fernet_key = self.data_overwrite()
            fernet = self.data_overwrite()
            key_file.write(encrypted_key)
            chmod(path.join(self.key_path,key_name), 0o600)
            self.immutable_data(key_name)
            print("Your password has been saved successfully!")
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
                    if checkpw(bytes(temp_entry), self.read_key_local()):
                         self.auxiliary_save_key(key_name,temp_entry,temp_encrypt,temp_fernet_key)
                         temp_entry = self.data_overwrite()
                         temp_encrypt = self.data_overwrite()
                         temp_fernet_key = self.data_overwrite()
                         break
                    else:
                        print("Incorrect password!")
                 else:
                    print("Password name already exists!")
      else:
          self.allowed_length_message()
          
      return
    
    def list_password(self):
            '''
            Lists all stored passwords except the .key file.
            '''
            listen = listdir(self.key_path) 
            for x in listen: 
                if x != ".key":
                   print(x)
            
    def inmutable_validation_delete(self,key_name):
          '''
          To avoid amplifying the immutable_data method, this validation was set up only for the delete method to ensure that it was only called if the immutable property exists.
          '''
          try:
            inmutable_validation = run(['/usr/bin/lsattr', path.join(self.key_path,key_name) ], text=True, check=True, capture_output=True)  
            if any('-i' in inm for inm in inmutable_validation.stdout.splitlines()):
               self.immutable_data(key_name)
          except CalledProcessError:
               print("Error validating immutability, failed to execute lsattr.")


    def delete(self):
          '''
          Deletes a specified key file after verifying the password.
          '''
          for _ in range(2):
             key_name = self.name_input()
             if not path.isfile(path.join(self.key_path,key_name)):
                 print("Error, Please enter an existing file name!")
                 exit(1)
             temp_entry = self.password_entry_validation()
             if checkpw(bytes(temp_entry), self.read_key_local()):
               temp_entry = self.data_overwrite()
               if key_name != ".key":
                 if (stat(path.join(self.key_path,key_name)).st_mode & 0o777) == 0o600:
                   self.inmutable_validation_delete(key_name)
                   remove(path.join(self.key_path,key_name))
                   print("The password has been successfully deleted!")
                   break
                 else:
                     print("The permissions were altered, for security the file will not be deleted!")
               else:
                   print("The unique key cannot be deleted!")
             else:
                print("Incorrect password!")
          return 
        

    def keep_safe(self,rute):
        '''
        Function that validates the existence of the directory and ensures that the set permissions are maintained.
        '''
        if not path.isdir(rute) and not path.isfile(rute):
              mkdir(rute)
              chmod(rute, 0o700)
        elif path.isdir(rute) or path.isfile(rute):
              chmod(rute, 0o700)

    
    def backup(self):
         '''
         Function that allows you to create a backup locally.
         '''
         for _ in range(2):
          temp_entry = self.password_entry_validation()
          if checkpw(bytes(temp_entry), self.read_key_local()):
            temp_entry = self.data_overwrite()
            files = listdir(self.key_path)
            path_backup = f"/home/{self.user}/.BacKupSV"
            self.keep_safe(path_backup)
            for file in files:
              if self.is_sanitized(file) and not path.isfile(path.join(path_backup,file + " " + str(datetime.now()))):
                copy(path.join(self.key_path,file),path.join(path_backup,file + " " + str(datetime.now())))
            print(f"The backup was created successfully in => {path_backup}")
            break
          else:
             print("Incorrect password!")
         return   

    def auxiliary_change_unique_key(self,file_name,current_fernet,new_fernet_key):
      '''
      Helper function that divides the tasks of the change_unique_key function
      '''
      if self.is_sanitized(file_name) and file_name != ".key":
            self.inmutable_validation_delete(file_name)
            with open(path.join(self.key_path, file_name), 'rb') as file_to_read:
                 encrypted_content = file_to_read.read()
                 decrypted_content = bytearray(current_fernet.decrypt(encrypted_content))
            with open(path.join(self.key_path, file_name), 'wb') as file_to_write:
                 new_fernet_encryptor = Fernet(bytes(new_fernet_key))
                 re_encrypted_content = new_fernet_encryptor.encrypt(bytes(decrypted_content))
                 file_to_write.write(re_encrypted_content)
                 chmod(path.join(self.key_path, file_name), 0o600)
                 self.immutable_data(file_name)
      current_fernet = self.data_overwrite()
      new_fernet_key = self.data_overwrite()
      decrypted_content = self.data_overwrite()
      new_fernet_encryptor = self.data_overwrite()
      return
        

    def change_unique_key(self):
      '''
      Function to change the unique encryption key securely.
      '''
      for _ in range(2):
        user_password = self.password_entry_validation()
        if checkpw(bytes(user_password), self.read_key_local()):
            current_fernet = Fernet(bytes(user_password))
            self.inmutable_validation_delete(".key")
            # Generate a new Fernet key and hash it
            new_fernet_key = bytearray(Fernet.generate_key())
            with open(path.join(self.key_path, ".key"), 'wb') as key_file:
                hashed_key = hashpw(bytes(new_fernet_key), gensalt())
                key_file.write(hashed_key)
                chmod(path.join(self.key_path, ".key"), 0o600)
                self.immutable_data(".key")
            print(f"Your new unique key is => {new_fernet_key.decode()}")
            # Re-encrypt all existing files with the new key
            key_files = listdir(self.key_path)
            for file_name in key_files:
               self.auxiliary_change_unique_key(file_name,current_fernet,new_fernet_key) 
            new_fernet_key = self.data_overwrite()
            user_password = self.data_overwrite()
            current_fernet = self.data_overwrite()
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
    python3 sv.py -c  change the unique key
Help Menu:
    -h  --help  print this help message and exit
                """)
        
        

    def temporary_key_encryption(self,temp_encrypt):
        '''
        Function that allows the encoding of the key generated by the generate_key method.
        '''
        key = bytearray(Fernet.generate_key())
        temp_fernet_key = Fernet(bytes(key))
        key = self.data_overwrite()
        temp_encrypt = temp_fernet_key.encrypt(bytes(temp_encrypt))
        self.save_key(temp_encrypt,temp_fernet_key)
        temp_fernet_key = self.data_overwrite()                                       
        return
        
        
    def validate_arguments(self):
        '''
        Function that validates the length and absence of malicious symbols. 
        '''
        if len(argv) >= 2 and not argv[1] in self.options:
             """
             A not was applied to the call of the is_sanitized method because it returns true, 
             and in this logical expression it would not be viable, since the validation of malicious
             symbols is applied in said named method and if everything is correct it returns true
             """
             if not self.is_sanitized(argv[1]) or len(argv) > 2 or len(argv[1]) > 7:
                  self.allowed_length_message()
                 
        elif len(argv) >= 3:
                  self.allowed_length_message()
                 

    def auxiliary_main(self):
         '''
         Helper function to split the tasks of the main function.
         '''
         signal(SIGTSTP, self.handle_tstp_signal)
         self.keep_safe(path.join(self.sv_path, "sv.py"))
         self.keep_safe(self.sv_path)
         self.keep_safe(self.key_path)
         self.validate_arguments()   

    
    def main(self):
        '''
        Main function, which will perform tasks based on the arguments given by the user.
        '''
        try:
            self.auxiliary_main()
            if self.options[2] in argv:
                temp_encrypt = bytearray(self.generate_key(),"utf-8")
                print(f"Key-Safe => {temp_encrypt.decode()}")
                self.temporary_key_encryption(temp_encrypt)
                temp_encrypt = self.data_overwrite()
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
            elif self.options[9] in argv:
                self.change_unique_key()
            else:
                print("SecureVault: invalid arguments. Use -g to generate a secure key. Try --help for more information.")
        except (KeyboardInterrupt,EOFError):
            print("\nOperation canceled by user!")
        except FileNotFoundError as e:
            print(f"Path or file does not exist => {e}")
        except PermissionError as p:
            print(f"Permissions error on the file or directory => {p}")
        except ValueError:
            print("The data you entered does not match the data requested!")   
        except InvalidToken:
            print("An error has occurred in the data encoding or decoding procedure!")
        except IsADirectoryError:
            print("Error, a directory has been detected!")
        except TypeError:  
            print("An error occurred while creating the backup!")
        except OSError:
           print("An error has occurred in the system that prevents the correct execution of the given function!")
        except UnicodeEncodeError:
           print("Text encoding error, please enter valid characters!")
        finally:  
           return
              
if __name__ == "__main__":
   try:
    #Gets the user who owns the sv.py file. 
    owner = getpwuid(stat(f"/home/{getuser()}/KeySafe/sv.py").st_uid).pw_name
    #Check that the script is not suspended for security reasons, (on some distros it may not work as expected, but this is unlikely)  
    process = run(['/usr/bin/ps', 'aux'], text=True, check=True, capture_output=True)
    output = [line for line in process.stdout.splitlines() if 'sv.py' in line]
    if not any('S+' in line for line in output):
       exit(1)
    elif getuser() != owner:
       print("Access denied!")
       exit(1)
    else:
       vault = SecureVault()
       vault.main()
           
   except CalledProcessError:
      print("Error running ps command!")
   except FileNotFoundError as e:
      print(f"Path or file does not exist => {e}")
   except (KeyError,ValueError,LookupError):
      print("Error getting owner of file sv.py!")
  
       
__name__="SecureVault"
__version__="1.0"
__author__="JP Rojas"
__license__="GPL"
__status__="Finish"
