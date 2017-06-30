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
    parser.add_argument("-ps", "--parsespeed", help="Define the value of the read/write in bytes of the file", default=512000, type=int)
    args = parser.parse_args()
    files = []
    if args.allfile != False:
        files = args.allfile()
    files = [os.path.basename(x) for x in files]
    if args.encrypt:
        encrypt(files, args.key, args.parsespeed)
    elif args.decrypt:
        decrypt(files, args.key, args.parsespeed)
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

def encrypt(files, password, parsespeed):
    print("[+]Starting the encryption protocole")
    for file in files:
        key = _key(password)
        encryptor = Fernet(key)
        print("\n[+]Encrypting", file)
        binary_crypt(file, encryptor, parsespeed, encr=1)

def binary_crypt(filename, cipher, parsespeed, encr=1):
    lenght = 0
    chunk = 0
    with open(filename, "rb") as file:
        file.seek(0, 2)
        lenght = file.tell()
        print("[+]Lenght file is:", lenght/1000000, "mb")
        file.seek(0)
        while True:
            if encr:
                data = cipher.encrypt(file.read(parsespeed))
                #data = base64.urlsafe_b64decode(data)
            else:
                data = cipher.decrypt(file.read(parsespeed))
                #data = base64.urlsafe_b64decode(data)
            writeb(filename, parsespeed, data, encr=encr)
            chunk += parsespeed
            file.seek(chunk)
            if chunk > lenght:
                break
            print("\r[*]Writing:", chunk/1000000, "mb", flush=True, end="")
def decrypt(files, password, parsespeed):
    print("[+]Starting the decryption protocole")
    for file in files:
        key = _key(password)
        decryptor = Fernet(key)
        print("\n[+]Decrypting", file)
        binary_crypt(file, decryptor, parsespeed, encr=0)

def writeb(file, parsespeed, data, encr=1):
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
