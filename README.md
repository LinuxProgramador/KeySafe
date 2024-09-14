SecureVault: Tool that allows me to generate and store secure passwords.

Note: To read and save secure keys, 
first generate the unique key with python3 sv.py -u, 
remember to save that key very well, 
because without it you will not be able to access your saved passwords

RECOMMENDED: Have a backup copy locally on an external storage drive of the unique key or (.key) and the keys generated from the KeySafe/.VaultSecret path, in case the owning user formats the system or accidentally deletes the .VaultSecret directory, and don't lose your keys.

Remember to keep script and module dependencies updated in requirements .txt

Note: To resume local backups, just copy to the KeySafe/ directory. VaultSecret and removing date

dependencies: (python3, python3-pip,e2fsprogs) 

use: 

NOTE:DO NOT USE AS ROOT USER!

cd ~ 

git clone https://github.com/LinuxProgramador/KeySafe

cd KeySafe 

chmod 700 sv.py 

Install dependencies (python3, python3-pip,e2fsprogs) 

Note: Arch Linux: (python, python-pip,e2fsprogs)

python3 -m pip install -r requirements.txt 

python3 sv.py -u   Run first to get the unique key which is the one you will be asked for whenever you want to perform an action within the script 

python3 sv.py [-h,--help,-V,-r,-g,-u,-d,-l,-b]
