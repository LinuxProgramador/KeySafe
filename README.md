SecureVault: tool that allows me to generate and store secure passwords.

Note: to read and save secure keys, 
first generate the unique key with python3 -u, 
remember to save that key very well, 
because without it you will not be able to access your saved passwords

Remember to keep script and module dependencies updated in requirements .txt

dependencies: (python3,pip) 

use: 

cd ~ 

git clone https://github.com/LinuxProgramador/KeySafe

cd KeySafe 

chmod 700 sv.py 

pip install -r requirements.txt 

python3 sv.py [-h,--help,-V,-r,-g,-u]
