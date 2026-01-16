import os
import socket
import json
from dotenv import load_dotenv, set_key
from fastecdsa import curve
from fastecdsa.point import Point

load_dotenv()

class KeyManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def recv_key_pair(self,HOST = "127.0.0.1",PORT = 8082):
        """
        Receives the public-private key pair from trusted authority.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((HOST, PORT))
            server.listen(1)
            print("[DT_DST] Waiting for key pair from Trusted Authority...")
            conn, addr = server.accept()
            with conn:
                print("[DT_DST] Connected by", addr)
                data = conn.recv(4096).decode("utf-8")
                key_pair = json.loads(data)
                set_key(".env", "PRIVATE_KEY", str(key_pair["sk_dst"]))
                set_key(".env", "PUBLIC_KEY_X", str(key_pair["pk_dst"]["x"]))
                set_key(".env", "PUBLIC_KEY_Y", str(key_pair["pk_dst"]["y"]))
                self.private_key = key_pair["sk_dst"]
                self.public_key = Point(key_pair["pk_dst"]["x"], key_pair["pk_dst"]["y"], curve.secp256k1)
                print("[DT_DST] Key pair received and stored in .env")

    def get_keys(self):
        """
        Retrieves the stored keys from the .env file or receives them from the trusted authority.
        """
        priv_key_str = os.getenv("PRIVATE_KEY")
        if not priv_key_str:
            self.recv_key_pair()
            return
        self.private_key = int(priv_key_str)
        pk_x = int(os.getenv("PUBLIC_KEY_X"))
        pk_y = int(os.getenv("PUBLIC_KEY_Y"))
        self.public_key = Point(pk_x, pk_y, curve.secp256k1)

def decrypt_data():
    """
    Decrypts the data received from the edge server.
    """
    return

def communicate_with_edge():
    """
    Communicates with the edge server to receive re-encrypted data.
    """
    return

if __name__ == "__main__":
    km = KeyManager()
    km.get_keys()
    sk = km.private_key
    pk = km.public_key 
    
    print(f"[DT_DST] Private Key: {sk}")
    print(f"[DT_DST] Public Key: ({pk.x}, {pk.y})")