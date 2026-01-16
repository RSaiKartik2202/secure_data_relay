import os
import socket
import json
from dotenv import load_dotenv, set_key
from fastecdsa.point import Point

load_dotenv()

class KeyManager:
    def __init__(self):
        self.reenc_key = None
    

    def recv_reencrypted_key(self, HOST="127.0.0.1", PORT=8083):
        """
        Receives the re-encrypted key from trusted authority.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((HOST, PORT))
            server.listen(1)
            print("[EDGE_SERVER] Waiting for re-encrypted key from Trusted Authority...")
            conn, addr = server.accept()
            with conn:
                print("[EDGE_SERVER] Connected by", addr)
                data = conn.recv(4096).decode("utf-8")
                reenc_key_data = json.loads(data)
                set_key(".env", "REENC_KEY", str(reenc_key_data["reenc_key"]))
                self.reenc_key = reenc_key_data["reenc_key"]
                print("[EDGE_SERVER] Re-encrypted key received and stored in .env")

    def get_reenc_key(self):
        """
        Retrieves the stored re-encrypted key from the .env file or receives it from the trusted authority.
        """
        renc_key_str = os.getenv("REENC_KEY")
        if not renc_key_str:
            self.recv_reencrypted_key()
            return
        self.reenc_key = int(renc_key_str)

def reencrypt_data():
    """
    Re-encrypts the data received from the originator digital twin.
    """
    return

def recv_encrypted_data():
    """
    Receives the encrypted data from the originator digital twin.
    """
    return

def send_reencrypted_data():
    """
    Sends the re-encrypted data to the destination digital twin.
    """
    return

if __name__ == "__main__":
    km = KeyManager()
    km.get_reenc_key()
    reenc_key = km.reenc_key
    print(f"[EDGE_SERVER] Re-encryption Key: {reenc_key}")