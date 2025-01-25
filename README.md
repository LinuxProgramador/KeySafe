SecureVault: A tool designed to generate and store secure passwords.

Recommended distributions:

    1. Ubuntu and its derivatives (such as Kubuntu, Xubuntu)

    2. ArchLinux

To restore local backups: simply copy them to the KeySafe/. VaultSecret path and remove the date, but first remove the immutable attribute from the keys in the . VaultSecret directory.

NOTE: Anti-data deletion protection only applies to keys within the directory. VaultSecret

NOTE: in Arch Linux and in some distros derived from Ubuntu, it is necessary to create a virtual environment to install the dependencies that are in the requirements.txt file

NOTE: Do not use symbols in password names 

Dependencies: python3, python3-pip, e2fsprogs, procps

Usage:

IMPORTANT: DO NOT RUN AS ROOT USER!

First, navigate to your home directory:

    cd ~

Clone the repository:

    git clone https://github.com/LinuxProgramador/KeySafe
    
Move into the KeySafe directory:

    cd KeySafe

Set the appropriate permissions for the script:

    chmod 700 sv.py

and

    chmod 600 requirements.txt

Install dependencies:

For most distributions, install with:

    sudo apt install python3 python3-pip e2fsprogs procps

For Arch Linux, use:

    sudo pacman -S python python-pip e2fsprogs procps

Then, install the Python dependencies:

    python3 -m pip install -r requirements.txt

Run the following command to generate the unique key, which will be required for any further actions within the script:

    python3 sv.py -u

Other commands:

python3 sv.py [-h, --help, -V, -r, -g, -u, -d, -l, -b, -c]

Remove unnecessary files, leaving only: sv.py, .VaultSecret, README.md, .git, requirements.txt.

How to create a virtual environment in Python3:

    python3 -m venv venv/path/to/venv

Using the virtual environment:

    venv/path/to/venv/bin/"and here the commands to execute"

Optional: Use ccrypt to apply an additional layer of encryption.

but first remove the immutability:

    sudo chattr -i "archivo aquí"
    
After encrypting with ccrypt, re-apply immutability:

    sudo chattr +i "archivo aquí"
    
Installation:

Ubuntu and derivatives:

    sudo apt install ccrypt -y

Arch Linux:

    sudo pacman -S ccrypt

Usage:

To encrypt:

    ccrypt -R .VaultSecret/

To decrypt:

    ccrypt -dR .VaultSecret/

change password:

    ccrypt -x -R .VaultSecret/

NOTE: Use a random key that is different from your unique key.

Version to compile:

Advantages of compiling:

    Ensures that the source code is not tampered with.

    Signing adds extra security.

    Note: Update dependencies regularly to keep the program secure.


Convert to executable:

Go to the KeySafe directory: 

    cd ~/KeySafe
    

Install the dependencies (including those in requirements.txt).

Install PyInstaller: 

    python3 -m pip install pyinstaller

Compile the program: 
    
    pyinstaller --onefile sv

Copy the executable: 
     
    cp -f dist/sv ./

Remove unnecessary files, leaving only:
sv, sv.sig, .VaultSecret, README.md, .git, requirements.txt.


Sign the executable:

Install GnuPG: 

    sudo apt update && sudo apt install gnupg -y

Create a GPG key: 
 
    gpg --full-generate-key

Sign the executable:

    gpg --detach-sign -o sv.sig sv


Verify the signature:

    gpg --verify sv.sig sv
