SecureVault: A tool designed to generate and store secure passwords.

Recommended distributions:

    1. Ubuntu and its derivatives (such as Kubuntu, Xubuntu)

    2. ArchLinux

To restore local backups: simply copy them to the KeySafe/. VaultSecret path and remove the date, but first remove the immutable attribute from the keys in the . VaultSecret directory.

NOTE: in Arch Linux and in some distros derived from Ubuntu, it is necessary to create a virtual environment to install the dependencies that are in the requirements.txt file

NOTE: Do not use symbols in password names 

Usage:

First, navigate to your home directory:

    cd ~

Clone the repository:

    git clone https://github.com/LinuxProgramador/KeySafe
    
Move into the KeySafe directory:

    cd KeySafe

Install dependencies:

For most distributions, install with:

    sudo apt install python3 python3-pip e2fsprogs procps

For Arch Linux, use:

    sudo pacman -S python python-pip e2fsprogs procps

Then, install the Python dependencies:

    python3 -m pip install -r requirements.txt

Convert to executable:

Install PyInstaller: 

    python3 -m pip install pyinstaller

Compile the program: 
    
    pyinstaller --onefile sv

Copy the executable: 
     
    cp -f dist/sv ./

Give execute permissions:

    chmod u+x sv

Sign the executable:

Install GnuPG: 

    sudo apt update && sudo apt install gnupg -y

Create a GPG key: 
 
    gpg --full-generate-key

Sign the executable:

    gpg --detach-sign -o sv.sig sv


Verify the signature:

    gpg --verify sv.sig sv

Run the following command to generate the unique key, which will be required for any further actions within the script:

    ./sv -u

Other commands:

./sv [-h, --help, -V, -r, -g, -u, -d, -l, -b, -c, -ck]

How to create a virtual environment in Python3:

    python3 -m venv venv/path/to/venv

Using the virtual environment:

    venv/path/to/venv/bin/"and here the commands to execute"



