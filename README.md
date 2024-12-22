SecureVault: A tool designed to generate and store secure passwords.

Recommended distributions:

    1. Ubuntu and its derivatives (such as Kubuntu, Xubuntu)

    2. ArchLinux

NOTE: To read and save secure keys, first generate the unique key by running python3 sv.py -u. Make sure to store this key securely, as you won’t be able to access your saved passwords without it.

RECOMMENDED: Keep a backup of the unique key (or .key file) on external storage, along with any keys saved in the KeySafe/.VaultSecret directory. This ensures that if the system is formatted or the .VaultSecret directory is accidentally deleted, you won’t lose access to your keys.

Remember to keep the script and module dependencies up-to-date by maintaining the requirements.txt file.

To restore local backups: simply copy them to the KeySafe/. VaultSecret path and remove the date, but first remove the immutable attribute from the keys in the . VaultSecret directory.

NOTE: Anti-data deletion protection only applies to keys within the directory. VaultSecret

NOTE: in Arch Linux and in some distros derived from Ubuntu, it is necessary to create a virtual environment to install the dependencies that are in the requirements.txt file

NOTE: when changing the unique key, it is recommended to execute the -b option first to have a backup of the keys in case there is a system interruption due to a power outage, etc....

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

Version to compile:

Advantages of compiling: 

it guarantees that the source code is not altered, and even more so if a signature is applied to it

NOTE: every time a dependency update is released, repeat this procedure to keep the program free of vulnerabilities 

Convert to executable:

access your KeySafe directory from the path ~/KeySafe 

then install the pyinstaller module 

python3 -m pip install pyinstaller 

pyinstaller --onefile sv 

cp -f dist/sv ./ 

then remove the remaining files, just leave the sv, .VaultSecret, README.md, .git and requirements.txt

Sign executable: 

1. install gnupg

   sudo apt update

   sudo apt install gnupg -y

3. Create a GPG key:

   gpg --full-generate-key

4. Sign the executable:

   gpg --detach-sign -o sv.sig  sv
 
5. Verify the signature:
 
   gpg --verify sv.sig  sv
