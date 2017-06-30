import os
import base64
import argparse
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("key", help="The password key")
    parser.add_argument("-e", "--encrypt", help="Encrypting mode", action="store_true", default=False)
    parser.add_argument("-d", "--decrypt", help="Decrypt mode", action="store_true", default=False)
    parser.add_argument("-f", "--file", help="adding file to crypt", action="append")
    parser.add_argument("-a", "--allfile", help="Get all file present in the current directory", action="store_const", const=get_dirfiles, default=False)
    args = parser.parse_args()
    files = []
    if args.allfile != False:
        files = args.allfile()
    files = [os.path.basename(x) for x in files]
    if args.encrypt:
        encrypt(files, args.key)
    elif args.decrypt:
        decrypt(files, args.key)
    else:
        print("[-]No mode choosen")
        exit()

def get_dirfiles():
    files = [f for f in os.listdir(os.getcwd()) if os.path.isfile(os.path.join(os.getcwd(), f))]
    if "Cryptio.py" in files:
        files.remove("Cryptio.py")
    return files

def _key(password):
    password = password.encode("utf8")
    hash = hashlib.new("sha256")
    hash.update(password)
    key = base64.urlsafe_b64encode(hash.digest())
    return key

def encrypt(files, password):
    print("[+]Starting the encryption protocole")
    key = _key(password)
    encryptor = Fernet(key)
    for file in files:
        print("\n[+]Encrypting", file)
        binary_crypt(file, encryptor, encr=1)

def binary_crypt(filename, cipher, step=512000, encr=1):
    lenght = 0
    chunk = 0
    with open(filename, "rb") as file:
        file.seek(0, 2)
        lenght = file.tell()
        print("[+]Lenght file is:", lenght/1000000, "mb")
        file.seek(0)
        while True:
            if encr:
                data = cipher.encrypt(file.read(step))
                #data = base64.urlsafe_b64decode(data)
            else:
                data = cipher.decrypt(file.read(step))
                #data = base64.urlsafe_b64decode(data)
            writeb(filename, step, data, encr=encr)
            chunk += step
            file.seek(chunk)
            if chunk > lenght:
                break
            print("\r[*]chunk:", chunk/1000000, "mb", flush=True, end="")
def decrypt(files, password):
    print("[+]Starting the decryption protocole")
    key = _key(password)
    decryptor = Fernet(key)
    for file in files:
        print("\n[+]Decrypting", file)
        try:
            binary_crypt(file, decryptor, encr=0)
        except:
            print("\n[-]Error, password may be not correct")
def writeb(file, step, data, encr=1):
    filename = ""
    if encr:
        filename = file + ".valin"
    else:
        filename = file.split(".")[0] + "." + file.split(".")[1]
    with open(filename, "ab") as f:
        f.write(data)

if __name__ == "__main__":
    os.system("cls")
    main()
