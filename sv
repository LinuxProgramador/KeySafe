#!/usr/bin/python3

#Tool to generate secure keys and store them safely on Linux distros

from sys import argv, exit
from signal import signal, SIGTSTP
    
#Known bug, does not handle the KeyboardInterrupt exception very well even if the try-except is applied
#The function below prevents the program from being suspended at startup using ctrl_z
def handle_tstp_signal(signum,frame):
    '''                                                                       
    Function that allows me to catch the signal produced by the ctrl_z key.
    '''
    try:
      print("\nOperation not allowed")
      exit(1)
    except NameError:
      exit(1)
    
signal(SIGTSTP, handle_tstp_signal)
    
from secrets import choice
from os import chmod, path, mkdir, remove, listdir, stat, urandom
from cryptography.fernet import Fernet, InvalidToken
from bcrypt import checkpw, hashpw, gensalt
from getpass import getpass, getuser
from string import ascii_lowercase, digits, ascii_uppercase
from subprocess import run, CalledProcessError
from shutil import copy
from datetime import datetime
from pwd import getpwuid
from time import sleep
from fcntl  import flock,LOCK_UN,LOCK_EX
    
    

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
        self.malicious_symbols = set("/+_-='~£¢€¥^✓§∆π√©®™•÷×?#;|&}!{][*>%<)($@:`,°\"\\")
        self.malicious_symbols_and_commands = set(["ping","ss","id","whoami", "groups","disown",
        "nohup","fg","bg","more","dir","ps","ls","cd","nano","vim","echo","cat","exec","wget",
        "curl","host","df","system","..","&&","||"])
        self.options = ['-d','-r','-g','-V','-l','-u','-h','--help','-b','-c','-ck']
        self.user = getuser()
        self.key_path = f"/home/{self.user}/KeySafe/.VaultSecret"
        self.sv_path = f"/home/{self.user}/KeySafe"

    def handle_tstp_signal(self,signum,frame):
       '''
       Function that allows me to catch the signal produced by the ctrl_z key.
       '''
       print("\nOperation not allowed")
       exit(1)
       

    def detect_framebuffer_access(self):
     '''
     (optional) Detects framebuffer access on the system
     '''
     #Detects framebuffer access to identify potential screen recording or unauthorized activity.
     try:
        """
        prompts the sudo password only once to cache it and prevent
        it from being requested repeatedly in subsequent commands during
        the same session.
        """
        run(['/usr/bin/sudo','-S','/usr/bin/true'])
        fb_access = run(["/usr/bin/lsof", "/dev/fb0"],text=True, check=True, capture_output=True)
        if any(recording in fb_access.stdout for recording in ['ffmpeg','x11grab']):
            print("Screen recording detected")
            exit(1)
     except (CalledProcessError,Exception):
           pass
     return

     
    def immutable_data(self,key):
       '''
       (optional) set user keys to immutable added anti-delete security.
       '''
       try:
        run(['/usr/bin/sudo','-S','/usr/bin/true'])
        list_attr_results = run(['/usr/bin/lsattr', path.join(self.key_path,key) ], text=True, check=True, capture_output=True)
        if any('-i' in line for line in list_attr_results.stdout.splitlines()):
           run(['/usr/bin/sudo', '/usr/bin/chattr', '-i', path.join(self.key_path,key) ], check=True, capture_output=True)
        elif not any('-i' in line for line in list_attr_results.stdout.splitlines()):
           run(['/usr/bin/sudo', '/usr/bin/chattr', '+i', path.join(self.key_path,key) ], check=True, capture_output=True)
       except CalledProcessError:
           pass
       return
           

    def lock_file(self,file_obj, lock_type):
       '''
       Applies a lock to a file using fcntl.
       '''
       for _ in range(3):
         try:
           flock(file_obj.fileno(), lock_type)
           return
         except IOError:
           print("Failed to lock the file")
           sleep(2)
       return

    def data_overwrite(self):
        '''
        Allows overwriting variable values by a 2048-bit salt.
        '''
        return urandom(2048)


    def allowed_length_message(self):
        '''
        Shows the user that they have exceeded the allowed character length
        '''
        print("Operation blocked: Length limit exceeded")
        exit(1)


    def generate_key(self):
       '''
        Generates a secure cryptographic key with a user-defined or default length.
       '''
       try:
        generated_key = bytearray("","utf-8")
        #length is hidden with "getpass" for security 
        query_longitude = int(getpass("Set key length (15-64) or press 0 to use the default: "))
        key_length = choice(range(15 ,65))
        if query_longitude:
         if len(str(query_longitude)) <= 3:
          if query_longitude >= 15 and query_longitude <= 64:
             key_length = query_longitude
          else:
             print("Number out of range; default value applied")
         else:
            self.allowed_length_message()
        characters = list(self.characters)
        for _ in range(key_length):
            char = bytearray(choice(characters),"utf-8")
            generated_key += char
        return generated_key
       finally:
         generated_key = self.data_overwrite()
         char = self.data_overwrite()
         key_length = self.data_overwrite()
         query_longitude = self.data_overwrite()
         
    def is_sanitized(self,entry):
     '''
      Checks if the provided entry contains any malicious symbols or commands.
     '''
     try:
      malicious_symbols_set = self.malicious_symbols | self.malicious_symbols_and_commands
      if path.isdir(entry) or path.isdir(path.join(self.key_path, entry)):
            print(f"Directory detected in {path.join(self.sv_path, entry)} or {path.join(self.key_path, entry)}, operation denied")
            exit(1)
      elif path.islink(entry) or path.islink(path.join(self.key_path, entry)):
            print(f"Symbolic link detected in {path.join(self.sv_path, entry)} or {path.join(self.key_path, entry)}, operation denied")
            exit(1)
      elif entry in malicious_symbols_set:
            print("Potential crash: Malicious symbol or command detected")
            exit(1)
      #Disables certain malicious symbols so that the unique key can be entered in base64.
      elif len(entry) == 44:
        sym = set([rm_sym for rm_sym in "/+_-=" if rm_sym in self.malicious_symbols])
        self.malicious_symbols.difference_update(sym)
      for char in entry:
         if char in self.malicious_symbols:
            print("Potential crash: Malicious symbol or command detected")
            exit(1)
      #It reactivates the malicious symbols after entering the user's password, thus maintaining security.
      self.malicious_symbols.update("/+_-=")
      return True
     finally:
        entry = self.data_overwrite()
        

    def password_entry_validation(self):
           '''
            Allows you to enter a key to validate with the stored password hash.
           '''
           try:
            sleep(2)
            frequent_user_entry = bytearray(getpass("Enter your unique key: ").strip().replace(" ",""),"utf-8")
            if frequent_user_entry:
              if self.is_sanitized(frequent_user_entry.decode()) and len(frequent_user_entry.decode()) <= 45:
                return frequent_user_entry
              else:
                self.allowed_length_message()
            else:
              frequent_user_entry = bytearray("0","utf-8")
              return frequent_user_entry
           finally:
               frequent_user_entry = self.data_overwrite()
               

    def read_key_local(self):
         '''
         read the hash of the key stored in the .key file.
         '''
         if self.is_sanitized(".key"):
           with open(path.join(self.key_path,".key"), 'rb') as key_file:
               try:
                self.lock_file(key_file, LOCK_EX)
                stored_hash = key_file.read()
                bcrypt_hash_validation = stored_hash.decode()
                if any(v in bcrypt_hash_validation[0:5] for v in ["2a$", "2b$", "2y$"]) and len(stored_hash) == 60:
                    return stored_hash
                else:
                    print(f"Error: \".key\" file corrupt. Restore backup and delete the file in => {self.key_path}")
                    exit(1)
               finally:
                flock(key_file.fileno(), LOCK_UN)
                      

    def name_input(self):
         '''
         Function to set the name of the file where the password is.
         '''
         key_name = input("Enter the name of your password: ").strip().replace(" ","")
         if key_name:
           if self.is_sanitized(key_name) and len(key_name) <= 40:
              return key_name
           else:
              self.allowed_length_message()
         else:
              return "NameDefault"


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
                   try:
                    self.lock_file(key_file, LOCK_EX)
                    encrypted_key = key_file.read()
                    fernet = Fernet(bytes(temp_entry))
                    temp_entry = self.data_overwrite()
                    decrypted_key = bytearray(fernet.decrypt(encrypted_key))
                    fernet = self.data_overwrite()
                    self.detect_framebuffer_access()
                    print(f"Your password is => {decrypted_key.decode()}")
                    decrypted_key = self.data_overwrite()
                    break
                   finally:
                    flock(key_file.fileno(), LOCK_UN)
              else:
                  print("Unable to read the unique key")
                  temp_entry = self.data_overwrite()
             else:
                print("Invalid password")
        return


    def hashAndSaveKey(self,key):
      '''
      Hashes the given key and saves it securely in a `.key`
      file with restricted permissions
      '''
      with open(path.join(self.key_path, ".key"), 'wb') as key_file:
        try:
         self.lock_file(key_file, LOCK_EX)
         hashed_key = hashpw(bytes(key), gensalt())
         key = self.data_overwrite()
         key_file.write(hashed_key)
         chmod(path.join(self.key_path, ".key"), 0o600)
         self.immutable_data(".key")
        finally:
         flock(key_file.fileno(), LOCK_UN)
      return


    def generate_unique_key(self):
        '''
        Stores a unique key by creating a .key file if it does not already exist.
        '''
        if not path.isfile(path.join(self.key_path,".key")):
            fernet_key = bytearray(Fernet.generate_key())
            self.hashAndSaveKey(fernet_key)
            self.detect_framebuffer_access()
            print(f"Its unique key is => {fernet_key.decode()}")
            fernet_key = self.data_overwrite()
        else:
            print("Password already exists")
        return


    def auxiliary_save_key(self,key_name,temp_entry,temp_encrypt,temp_fernet_key):
      '''
      Helper function that divides the tasks of the save_key function
      '''
      with open(path.join(self.key_path,key_name), 'wb') as key_file:
           try:
            self.lock_file(key_file, LOCK_EX)
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
            print("Password saved successfully")
           finally:
            flock(key_file.fileno(), LOCK_UN)
      return


    def save_key(self,temp_encrypt,temp_fernet_key):
      '''
      Saves a generated key to a specified file, after verifying the password.
      '''
      confirm = input("Save password? (y/n): ").strip().lower()
      if not confirm:
          confirm = "n"
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
                        print("Invalid password")
                 else:
                    print("Password name already in use")
      else:
          self.allowed_length_message()

      return

    def list_password(self):
            '''
            Lists all stored passwords except the .key file.
            '''
            keys = listdir(self.key_path)
            for key in keys:
                if not any(key in key_unique for key_unique in [".key",".key.cpt"]):
                   print(key)

    def validation_existence_immutability(self,key_name):
          '''
          To avoid amplifying the immutable_data method, this validation was set up only for the delete method to ensure that it was only called if the immutable property exists.
          '''
          try:
            inmutable_validation = run(['/usr/bin/lsattr', path.join(self.key_path,key_name) ], text=True, check=True, capture_output=True)
            if any('-i' in inm for inm in inmutable_validation.stdout.splitlines()):
               self.immutable_data(key_name)
          except CalledProcessError:
               print("Error validating immutability: lsattr execution failed")
          return

    def delete_key(self):
          '''
          Deletes a specified key file after verifying the password.
          '''
          for _ in range(2):
             key_name = self.name_input()
             if not path.isfile(path.join(self.key_path,key_name)):
                 print("Error: Please enter a valid file name")
                 exit(1)
             temp_entry = self.password_entry_validation()
             if checkpw(bytes(temp_entry), self.read_key_local()):
               temp_entry = self.data_overwrite()
               if key_name != ".key":
                 if (stat(path.join(self.key_path,key_name)).st_mode & 0o777) == 0o600:
                   self.validation_existence_immutability(key_name)
                   remove(path.join(self.key_path,key_name))
                   print("Password deleted successfully")
                   break
                 else:
                     print("Permissions altered; file not deleted for security")
               else:
                   print("Unique key cannot be deleted")
             else:
                print("Invalid password")
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
        return

    def backup(self):
         '''
         Function that allows you to create a backup locally.
         '''
         for _ in range(2):
          temp_entry = self.password_entry_validation()
          if checkpw(bytes(temp_entry), self.read_key_local()):
            temp_entry = self.data_overwrite()
            keys = listdir(self.key_path)
            path_backup = f"/home/{self.user}/.BacKupSV"
            self.keep_safe(path_backup)
            for key in keys:
              date_and_time = datetime.now().strftime("%Y-%m-%d %H:%M")
              if self.is_sanitized(key) and not path.isfile(path.join(path_backup,key + " " + date_and_time )):
                copy(path.join(self.key_path,key),path.join(path_backup,key + " " + date_and_time ))
            print(f"Backup created successfully in => {path_backup}")
            break
          else:
             print("Invalid password")
         return

    def auxiliary_change_unique_key(self,key,fernet_old_key,new_fernet_key):
      '''
      Helper function that divides the tasks of the change_unique_key function
      '''
      if self.is_sanitized(key) and key != ".key":
            self.validation_existence_immutability(key)
            with open(path.join(self.key_path, key), 'rb') as file_to_read:
                try:
                 self.lock_file(file_to_read, LOCK_EX)
                 encrypted_content = file_to_read.read()
                 decrypted_content = bytearray(fernet_old_key.decrypt(encrypted_content))
                finally:
                 flock(file_to_read.fileno(), LOCK_UN)
            with open(path.join(self.key_path, key), 'wb') as file_to_write:
                try:
                 self.lock_file(file_to_write, LOCK_EX)
                 fernet_new_key = Fernet(bytes(new_fernet_key))
                 encrypted_content = fernet_new_key.encrypt(bytes(decrypted_content))
                 file_to_write.write(encrypted_content)
                 chmod(path.join(self.key_path, key), 0o600)
                 self.immutable_data(key)
                finally:
                 flock(file_to_write.fileno(), LOCK_UN)
      fernet_old_key = self.data_overwrite()
      new_fernet_key = self.data_overwrite()
      decrypted_content = self.data_overwrite()
      fernet_new_key = self.data_overwrite()
      return


    def change_unique_key(self):
      '''
      Function to change the unique encryption key securely.
      '''
      for _ in range(2):
        temp_entry = self.password_entry_validation()
        if checkpw(bytes(temp_entry), self.read_key_local()):
            fernet_old_key = Fernet(bytes(temp_entry))
            self.validation_existence_immutability(".key")
            # Generate a new Fernet key and hash it
            new_fernet_key = bytearray(Fernet.generate_key())
            self.hashAndSaveKey(new_fernet_key)
            print(f"Your new unique key is => {new_fernet_key.decode()}")
            # Re-encrypt all existing files with the new key
            keys = listdir(self.key_path)
            for key in keys:
                 self.auxiliary_change_unique_key(key,fernet_old_key,new_fernet_key)
            new_fernet_key = self.data_overwrite()
            temp_entry = self.data_overwrite()
            fernet_old_key = self.data_overwrite()
            break
        else:
            print("Invalid password")
      return


    def show_help(self):
        '''
        When the function is called, it prints the help menu.
        '''
        print("SecureVault 1.0. It is a tool that allows you to generate secure keys.")
        print("""
Usage:
    ./sv -g  generate a secure key
    ./sv -V  print version info and exit
    ./sv -r  read a stored password by its custom name
    ./sv -u  generate a unique key
    ./sv -d  delete secure key
    ./sv -l  list your stored passwords
    ./sv -b  create a backup locally
    ./sv -c  change the unique key
    ./sv -ck Stores a user-customized key
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
                  

    def validation_nonexistence_immutability(self):
          '''
            This method checks the immutability of files in self.key_path and sets them as immutable if they are not.
          '''
          try:
            keys = listdir(self.key_path)
            for key in keys:
              inmutable_validation = run(['/usr/bin/lsattr', path.join(self.key_path,key) ], text=True, check=True, capture_output=True)
              if not any('-i' in inm for inm in inmutable_validation.stdout.splitlines()):
                 self.immutable_data(key)
          except CalledProcessError:
            print("Error validating immutability: lsattr execution failed")
          return
          
    def save_custom_key(self):
        '''
         Stores a user-provided custom key securely.
        '''
        key_name_list = {"key":None}
        for _ in range(2):
          key_name = self.name_input()
          temp_entry = self.password_entry_validation()
          if checkpw(bytes(temp_entry), self.read_key_local()):
            with open(path.join(self.key_path,key_name),'wb') as write_file:
             try:
               self.lock_file(write_file, LOCK_EX)
               key_name_list["key"] = bytearray(getpass("Enter your custom key: "),"utf-8")
               if not 1 <= len(key_name_list["key"].decode()) <= 65:
                   print("The key must be between 1 and 65 characters")
                   exit(1)
               fernet = Fernet(bytes(temp_entry))
               temp_entry = self.data_overwrite()
               encrypted_key = fernet.encrypt(bytes(key_name_list["key"]))
               fernet = self.data_overwrite()
               key_name_list["key"] = self.data_overwrite()
               write_file.write(encrypted_key)
               chmod(path.join(self.key_path,key_name), 0o600)
               self.immutable_data(key_name)
               print("Password saved successfully")
               break
             finally:
               flock(write_file.fileno(), LOCK_UN)
          else:
             print("Invalid password")
          return
             
    def auxiliary_main(self):
         '''
         Helper function to split the tasks of the main function.
         '''
         signal(SIGTSTP, self.handle_tstp_signal)
         self.keep_safe(path.join(self.sv_path, "sv"))
         self.keep_safe(self.sv_path)
         self.keep_safe(self.key_path)
         self.validate_arguments()
         self.validation_nonexistence_immutability()
         return

    def main(self):
        '''
        Main function, which will perform tasks based on the arguments given by the user.
        '''
        try:
            self.auxiliary_main()
            if self.options[2] in argv:
                temp_encrypt = self.generate_key()
                self.detect_framebuffer_access()
                print(f"Key-Safe => {temp_encrypt.decode()}")
                self.temporary_key_encryption(temp_encrypt)
                temp_encrypt = self.data_overwrite()
            elif self.options[3] in argv:
                print("SecureVault 1.0. It is a tool that allows you to generate secure keys.")
            elif self.options[5] in argv:
                self.generate_unique_key()
            elif self.options[1] in argv:
                self.read_key()
            elif self.options[0] in argv:
                self.delete_key()
            elif self.options[4] in argv:
                self.list_password()
            elif self.options[6] in argv or self.options[7] in argv:
                self.show_help()
            elif self.options[8] in argv:
                self.backup()
            elif self.options[9] in argv:
                self.change_unique_key()
            elif self.options[10] in argv:
                 self.save_custom_key()
            else:
                print("SecureVault: invalid arguments. Use -g to generate a secure key. Try --help for more information.")
        except (KeyboardInterrupt,EOFError):
            print("\nOperation aborted by the user")
        except FileNotFoundError as e:
            print(f"Path or file not found => {e}")
        except PermissionError as p:
            print(f"Permissions error on file or directory => {p}")
        except ValueError:
            print("Entered data does not match the requested data")
        except InvalidToken:
            print("Error in data encoding or decoding")
        except IsADirectoryError:
            print("Error: Directory detected")
        except TypeError:
            print("Error creating backup")
        except OSError:
           print("System error preventing function execution")
        except UnicodeEncodeError:
           print("Text encoding error; please use valid characters")
        finally:
           return

if __name__ == "__main__":
   try:
    #Gets the user who owns the sv file.
    owner = getpwuid(stat(f"/home/{getuser()}/KeySafe/sv").st_uid).pw_name
    #Check that the script is not suspended for security reasons, (on some distros it may not work as expected, but this is unlikely)
    process = run(['/usr/bin/ps', 'aux'], text=True, check=True, capture_output=True)
    line = [line for line in process.stdout.splitlines() if 'sv' in line]
    if not process.stdout.count("sv") in [3,4] or not any('S+' in word for word in line) and not any('S<+' in word for word in line):
       #The "pass" is set and then closed with "finally"
       pass
    elif getuser() != owner or getuser() == "root":
       print("Access denied!")
       
    else:
       vault = SecureVault()
       vault.main()

   except CalledProcessError:
      print("Error running ps command")
   except FileNotFoundError as e:
      print(f"Path or file not found => {e}")
   except (KeyError,ValueError,LookupError):
      print("Error retrieving file owner for sv")
   finally:
      exit(1)
      

__name__="SecureVault"
__version__="1.0"
__author__="JP Rojas"
__license__="GPL"
__status__="Finish"
