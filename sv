#!/usr/bin/python3

#Tool to generate secure keys and store them safely on Linux distros

from sys import argv, exit
from signal import signal, SIGTSTP
    
#Known bug; does not handle the KeyboardInterrupt exception very well even if the try-except is applied
#Known bug; if you pass a long string when running the program, it tends to not display the print output message, but it does exit correctly as set.
#The function below prevents the program from being suspended at startup using ctrl_z
def handle_tstp_signal(signum,frame):
    ''' Function that allows me to catch the signal produced by the ctrl_z key.'''
    print("\nOperation not allowed")
    exit(1)
      
signal(SIGTSTP, handle_tstp_signal)
    
from secrets import choice
from os import chmod, path, mkdir, remove, listdir, stat, urandom, environ
from cryptography.fernet import Fernet, InvalidToken
from bcrypt import checkpw, hashpw, gensalt
from getpass import getpass, getuser
from string import ascii_lowercase, digits, ascii_uppercase
from subprocess import run, CalledProcessError
from shutil import copy
from datetime import datetime
from pwd import getpwuid
from time import sleep, perf_counter
from fcntl import flock,LOCK_UN,LOCK_EX


environ.clear()
environ["PATH"] = "/usr/bin:/bin"
environ["HOME"] = path.expanduser("~")
environ["LANG"] = "C.UTF-8"           
environ["TERM"] = "xterm-256color"      
    
class SecureVault:
    ''' SecureVault class provides functionalities to generate, store, and manage cryptographic keys.'''
    def __init__(self):
        ''' Initializes the SecureVault instance with default values.  '''
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
      

    def detect_framebuffer_access(self):
     '''  (optional) Detects framebuffer access on the system  '''
     #Detects framebuffer access to identify potential screen recording or unauthorized activity.
     try:
        """
        prompts the sudo password only once to cache it and prevent
        it from being requested repeatedly in subsequent commands during
        the same session.
        """
        run(['/usr/bin/sudo','-S','/usr/bin/true'], env=environ.copy())
        fb_access = run(["/usr/bin/sudo", "/usr/bin/lsof", "/dev/fb0"],text=True, check=True, capture_output=True, env=environ.copy())
        # More screen recorders can be added
        if any(recording in fb_access.stdout for recording in ['ffmpeg','x11grab']):
            print("Screen recording detected")
            exit(1)
     except (CalledProcessError,Exception):
           pass
     return

     
    def immutable_data(self,key):
       '''  (optional) set user keys to immutable added anti-delete security.  '''
       try:
        run(['/usr/bin/sudo','-S','/usr/bin/true'], env=environ.copy())
        list_attr_results = run(['/usr/bin/lsattr', path.join(self.key_path,key) ], text=True, check=True, capture_output=True, env=environ.copy())
        if any('-i' in line for line in list_attr_results.stdout.splitlines()):
           run(['/usr/bin/sudo', '/usr/bin/chattr', '-i', path.join(self.key_path,key) ], check=True, capture_output=True, env=environ.copy())
        elif not any('-i' in line for line in list_attr_results.stdout.splitlines()):
           run(['/usr/bin/sudo', '/usr/bin/chattr', '+i', path.join(self.key_path,key) ], check=True, capture_output=True, env=environ.copy())
       except CalledProcessError:
           pass
       return
           
      
    def lock_file(self,file_obj, lock_type):
       '''   Applies a lock to a file using fcntl.  '''
       for _ in range(3):
         try:
           flock(file_obj.fileno(), lock_type)
           return
         except (IOError,Exception):
           print("Failed to lock the file")
           sleep(2)
       return

    def allowed_length_message(self):
        '''   Shows the user that they have exceeded the allowed character length  '''
        print("Operation blocked: Length limit exceeded")
        exit(1)


    def generate_key(self):
        '''  Generates a secure cryptographic key with a user-defined or default length '''
        constant_duration = 4.0
        start_time = perf_counter()
        generated_key = bytearray("","utf-8")
        #length is hidden with "getpass" for security 
        query_longitude = int(getpass("Set key length (15-64) or press 0 to use the default: ").strip())
        key_length = choice(range(15 ,65))
        if query_longitude:
         if len(str(query_longitude)) <= 3:
          if 15 <= query_longitude <= 64:
             key_length = query_longitude
          else:
             print("Number out of range; default value applied")
         else:
            self.allowed_length_message()
        characters = list(self.characters)
        for _ in range(key_length):
            char = bytearray(choice(characters),"utf-8")
            generated_key += char
        elapsed = perf_counter() - start_time
        if elapsed < constant_duration:
           sleep(constant_duration - elapsed)
        return generated_key
         
    def is_sanitized(self,entry):
      '''   Checks if the provided entry contains any malicious symbols or commands   '''
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

    def password_entry_validation(self):
            '''   Allows you to enter a key to validate with the stored password hash.  '''
            sleep(2)
            frequent_user_entry = bytearray(getpass("Enter your unique key: ").strip().replace(" ",""),"utf-8")
            if frequent_user_entry:
              if self.is_sanitized(frequent_user_entry.decode()) and len(frequent_user_entry.decode()) <= 45:
                if len(frequent_user_entry.decode()) == 44:
                  try:
                     key = frequent_user_entry
                     token = Fernet(bytes(key)).encrypt(b"Test")
                     f = Fernet(bytes(key))
                     f.decrypt(token)
                  except (ValueError, InvalidToken):
                     print("Password does not meet the required format")
                     exit(1)
                return frequent_user_entry
              else:
                self.allowed_length_message()
            else:
              frequent_user_entry = bytearray("0","utf-8")
              return frequent_user_entry     

    def read_key_local(self):
         '''   read the hash of the key stored in the .key file.   '''
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
         '''   Function to set the name of the file where the password is  '''
         key_name = input("Enter the name of your password: ").strip().replace(" ","")
         if key_name:
           if self.is_sanitized(key_name) and len(key_name) <= 40:
              return key_name
           else:
              self.allowed_length_message()
         else:
              return "NameDefault"


    def read_key(self):
          '''  Reads a stored key by prompting the user for its name and verifying the password  ''' 
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
                    decrypted_key = bytearray(fernet.decrypt(encrypted_key))
                    self.detect_framebuffer_access()
                    print(f"Your password is => {decrypted_key.decode()}")
                    temp_entry[:] = urandom(len(temp_entry.decode()))
                    decrypted_key[:] = urandom(len(decrypted_key.decode()))
                    break
                   finally:
                    flock(key_file.fileno(), LOCK_UN)
              else:
                  print("Unable to read the unique key")
                  temp_entry[:] = urandom(len(temp_entry.decode()))
             else:
                print("Invalid password")
          return

    def hashAndSaveKey(self,key):
       '''Hashes the given key and saves it securely in a `.key`
       file with restricted permissions '''
       with open(path.join(self.key_path, ".key"), 'wb') as key_file:
        try:
         self.lock_file(key_file, LOCK_EX)
         hashed_key = hashpw(bytes(key), gensalt())
         key_file.write(hashed_key)
         chmod(path.join(self.key_path, ".key"), 0o600)
         self.immutable_data(".key")
        finally:
         flock(key_file.fileno(), LOCK_UN)
       return

    def generate_unique_key(self):
         ''' Stores a unique key by creating a .key file if it does not already exist. '''
         if not path.isfile(path.join(self.key_path,".key")):
            fernet_key = bytearray(Fernet.generate_key())
            self.hashAndSaveKey(fernet_key)
            self.detect_framebuffer_access()
            print(f"Its unique key is => {fernet_key.decode()}")
            fernet_key[:] = urandom(len(fernet_key.decode()))
         else:
            print("Password already exists")
         return

    def auxiliary_save_key(self,key_name,temp_entry,temp_encrypt,temp_fernet_key):
       '''   Helper function that divides the tasks of the save_key function '''
       with open(path.join(self.key_path,key_name), 'wb') as key_file:
           try:
            self.lock_file(key_file, LOCK_EX)
            fernet = Fernet(bytes(temp_entry))
            temp_encrypt = bytearray(temp_fernet_key.decrypt(temp_encrypt))
            encrypted_key = fernet.encrypt(bytes(temp_encrypt))
            key_file.write(encrypted_key)
            chmod(path.join(self.key_path,key_name), 0o600)
            self.immutable_data(key_name)
            print("Password saved successfully")
            temp_entry[:] = urandom(len(temp_entry.decode()))
            temp_encrypt[:] = urandom(len(temp_encrypt.decode()))
           finally:
            flock(key_file.fileno(), LOCK_UN)
       return
        
    def save_key(self,temp_encrypt,temp_fernet_key):
       ''' Saves a generated key to a specified file, after verifying the password.  '''
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
                         break
                    else:
                        print("Invalid password")
                 else:
                    print("Password name already in use")
       else:
          self.allowed_length_message()

       return

    def list_password(self):
            '''Lists all stored passwords except the .key file. '''
            keys = listdir(self.key_path)
            for key in keys:
                if not key in [".key"]:
                   print(key)

    def validation_existence_immutability(self,key_name):
          ''' To avoid amplifying the immutable_data method, this validation was set up only for the delete method to ensure that it was only called if the immutable property exists.'''
          try:
            inmutable_validation = run(['/usr/bin/lsattr', path.join(self.key_path,key_name) ], text=True, check=True, capture_output=True, env=environ.copy())
            if any('-i' in inm for inm in inmutable_validation.stdout.splitlines()):
               self.immutable_data(key_name)
          except CalledProcessError:
               print("Error validating immutability: lsattr execution failed")
          return

    def delete_key(self):
           '''  Deletes a specified key file after verifying the password.  '''
           for _ in range(2):
             key_name = self.name_input()
             if not path.isfile(path.join(self.key_path,key_name)):
                 print("Error: Please enter a valid file name")
                 exit(1)
             temp_entry = self.password_entry_validation()
             if checkpw(bytes(temp_entry), self.read_key_local()):
               if key_name != ".key":
                 if (stat(path.join(self.key_path,key_name)).st_mode & 0o777) == 0o600:
                   self.validation_existence_immutability(key_name)
                   remove(path.join(self.key_path,key_name))
                   print("Password deleted successfully")
                   temp_entry[:] = urandom(len(temp_entry.decode()))
                   break
                 else:
                     print("Permissions altered; file not deleted for security")
                     temp_entry[:] = urandom(len(temp_entry.decode()))
               else:
                   print("Unique key cannot be deleted")
                   temp_entry[:] = urandom(len(temp_entry.decode()))
             else:
                print("Invalid password")
           return

    def keep_safe(self,rute):
        ''' Function that validates the existence of the directory and ensures that the set permissions are maintained.'''
        if not path.isdir(rute) and not path.isfile(rute):
              mkdir(rute)
              chmod(rute, 0o700)
        elif path.isdir(rute) or path.isfile(rute):
              chmod(rute, 0o700)
        return

    def backup(self):
          ''' Function that allows you to create a backup locally.'''
          for _ in range(2):
           temp_entry = self.password_entry_validation()
           if checkpw(bytes(temp_entry), self.read_key_local()):
            temp_entry[:] = urandom(len(temp_entry.decode()))
            keys = listdir(self.key_path)
            path_backup = f"/home/{self.user}/.BacKupSV"
            self.keep_safe(path_backup)
            for key in keys:
              date_and_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
              if self.is_sanitized(key) and not path.isfile(path.join(path_backup,key + " " + date_and_time )):
                copy(path.join(self.key_path,key),path.join(path_backup,key + " " + date_and_time ))
            print(f"Backup created successfully in => {path_backup}")
            break
           else:
             print("Invalid password")
          return

    def auxiliary_change_unique_key(self,key,fernet_old_key,new_fernet_key):
       ''' Helper function that divides the tasks of the change_unique_key function '''
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
                 decrypted_content[:] = urandom(len(decrypted_content.decode()))
       return

    def change_unique_key(self):
       '''Function to change the unique encryption key securely.'''
       for _ in range(2):
        temp_entry = self.password_entry_validation()
        if checkpw(bytes(temp_entry), self.read_key_local()):
            fernet_old_key = Fernet(bytes(temp_entry))
            self.validation_existence_immutability(".key")
            # Generate a new Fernet key and hash it
            new_fernet_key = bytearray(Fernet.generate_key())
            self.hashAndSaveKey(new_fernet_key)
            self.detect_framebuffer_access()
            print(f"Your new unique key is => {new_fernet_key.decode()}")
            # Re-encrypt all existing files with the new key
            keys = listdir(self.key_path)
            for key in keys:
                 self.auxiliary_change_unique_key(key,fernet_old_key,new_fernet_key)
            temp_entry[:] = urandom(len(temp_entry.decode()))
            new_fernet_key[:] = urandom(len(new_fernet_key.decode()))
            break
        else:
            print("Invalid password")
       return

    def show_help(self):
        ''' When the function is called, it prints the help menu. '''
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
    ./sv -ck stores a user-customized key
Help Menu:
    -h  --help  print this help message and exit
                """)

    def temporary_key_encryption(self,temp_encrypt):
        ''' Function that allows the encoding of the key generated by the generate_key method. '''
        key = bytearray(Fernet.generate_key())
        key_remove = key
        temp_fernet_key = Fernet(bytes(key))
        temp_encrypt_remove = temp_encrypt
        temp_encrypt = temp_fernet_key.encrypt(bytes(temp_encrypt))
        self.save_key(temp_encrypt,temp_fernet_key)
        temp_encrypt_remove[:] = urandom(len(temp_encrypt_remove.decode()))
        key_remove[:] = urandom(len(key_remove.decode()))
        return
        
    def validate_arguments(self):
        ''' Function that validates the length and absence of malicious symbols.  '''
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
        return
                  

    def validation_nonexistence_immutability(self):
          ''' This method checks the immutability of files in self.key_path and sets them as immutable if they are not. '''
          try:
            keys = listdir(self.key_path)
            for key in keys:
              if path.isfile(path.join(self.key_path,key)):
                inmutable_validation = run(['/usr/bin/lsattr', path.join(self.key_path,key) ], text=True, check=True, capture_output=True, env=environ.copy())
                if not any('-i' in inm for inm in inmutable_validation.stdout.splitlines()):
                  self.immutable_data(key)
          except CalledProcessError:
            print("Error validating immutability: lsattr execution failed")
          return
        
    def auxiliary_save_custom_key(self,key_name,temp_entry,key_name_list):
        ''' Saves an encrypted key in a file with secure locking and permissions. '''
        with open(path.join(self.key_path,key_name),'wb') as write_file:
             try:
               self.lock_file(write_file, LOCK_EX)
               fernet = Fernet(bytes(temp_entry))
               encrypted_key = fernet.encrypt(bytes(key_name_list["key"]))
               write_file.write(encrypted_key)
               chmod(path.join(self.key_path,key_name), 0o600)
               self.immutable_data(key_name)
               print("Password saved successfully")
             finally:
               flock(write_file.fileno(), LOCK_UN)
        return

    def save_custom_key(self):
         '''  Stores a user-provided custom key securely. '''
         key_name_list = {"key":None}
         for _ in range(2):
          key_name = self.name_input()
          if not path.isfile(path.join(self.key_path,key_name)):
           temp_entry = self.password_entry_validation()
           if checkpw(bytes(temp_entry), self.read_key_local()):
            key_name_list["key"] = bytearray(getpass("Enter your custom key: ").strip(),"utf-8")
            if path.islink(key_name_list["key"].decode()) or path.isdir(key_name_list["key"].decode()) or path.isfile(key_name_list["key"].decode()):
               print("You entered a path to a directory, symbolic link or file; operation not permitted")
               exit(1)
            if not 1 <= len(key_name_list["key"].decode()) <= 65:
               print("The key must be between 1 and 65 characters")
               exit(1)
            self.auxiliary_save_custom_key(key_name,temp_entry,key_name_list)
            temp_entry[:] = urandom(len(temp_entry.decode()))
            key_name_list_temp = key_name_list["key"]
            key_name_list_temp[:] = urandom(len(key_name_list_temp.decode()))
            break
           else:
              print("Invalid password")
          else:
             print("Password name already in use")
         return
            
    def auxiliary_main(self):
         ''' Helper function to split the tasks of the main function.'''
         self.keep_safe(path.join(self.sv_path, "sv"))
         self.keep_safe(self.sv_path)
         self.keep_safe(self.key_path)
         self.validate_arguments()
         self.validation_nonexistence_immutability()
         return

    def main(self):
        ''' Main function, which will perform tasks based on the arguments given by the user.'''
        try:
            self.auxiliary_main()
            if self.options[2] in argv:
                temp_encrypt = self.generate_key()
                self.detect_framebuffer_access()
                print(f"Key-Safe => {temp_encrypt.decode()}")
                self.temporary_key_encryption(temp_encrypt)
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
        return

if __name__ == "__main__":
   try:
    #Gets the user who owns the sv file.
    owner = getpwuid(stat(f"/home/{getuser()}/KeySafe/sv").st_uid).pw_name
    #Check that the script is not suspended for security reasons, (on some distros it may not work as expected, but this is unlikely)
    process = run(['/usr/bin/ps', 'aux'], text=True, check=True, capture_output=True, env=environ.copy())
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
