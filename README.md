SecureVault: A tool designed to generate and store secure passwords.

Note: To read and save secure keys, first generate the unique key by running python3 sv.py -u. Make sure to store this key securely, as you won’t be able to access your saved passwords without it.

RECOMMENDED: Keep a backup of the unique key (or .key file) on external storage, along with any keys saved in the KeySafe/.VaultSecret directory. This ensures that if the system is formatted or the .VaultSecret directory is accidentally deleted, you won’t lose access to your keys.

Remember to keep the script and module dependencies up-to-date by maintaining the requirements.txt file.

To restore local backups: Simply copy the .VaultSecret folder back into the KeySafe/ directory, and remove any date stamps.

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

python3 sv.py [-h, --help, -V, -r, -g, -u, -d, -l, -b]

