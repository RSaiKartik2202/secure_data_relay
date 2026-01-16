import os
import socket
import json
import time
from dotenv import load_dotenv, set_key
from fastecdsa import curve
from fastecdsa.point import Point

load_dotenv()

DESTINATION_REGISTRY = {
    "DT_2": ("127.0.0.1", 8090),
}

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


class EdgeServer:
    def __init__(self, reenc_key, host="127.0.0.1", port=8084):
        self.reenc_key = reenc_key
        self.host = host
        self.port = port

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((self.host, self.port))
            server.listen(5)
            print("[EDGE_SERVER] Listening for encrypted data...")

            while True:
                conn, addr = server.accept()
                with conn:
                    self.handle_connection(conn, addr)

    def handle_connection(self, conn, addr):
        print("[EDGE_SERVER] Connection from", addr)
        buffer = ""

        while True:
            chunk = conn.recv(4096).decode("utf-8")
            if not chunk:
                break
            buffer += chunk
            if "\n" in buffer:
                break

        payload = json.loads(buffer.strip())
        self.process_payload(payload)

    def process_payload(self, data):
        Torg = data["Torg"]
        if abs(time.time() - Torg) > 10:
            print("[EDGE_SERVER] Dropping message: stale timestamp")
            return

        CT = Point(
            data["c_t"]["x"],
            data["c_t"]["y"],
            curve.secp256k1
        )
        CM = Point(
            data["c_m"]["x"],
            data["c_m"]["y"],
            curve.secp256k1
        )

        # Re-encryption: C_T' = rk * C_T
        CT_prime = self.reenc_key * CT

        dst_id = data["dest_dt_id"]
        if dst_id not in DESTINATION_REGISTRY:
            print("[EDGE_SERVER] Unknown destination:", dst_id)
            return


        self.forward_to_destination(
            dst_id,
            CT_prime,
            CM,
            data["hM"],
            time.time()
        )

    def forward_to_destination(self, dst_id, CT_prime, CM, hM, Tproxy):
        host, port = DESTINATION_REGISTRY[dst_id]

        payload = {
            "curve": "secp256k1",
            "c_t_prime": {
                "x": CT_prime.x,
                "y": CT_prime.y
            },
            "c_m": {
                "x": CM.x,
                "y": CM.y
            },
            "hM": hM,
            "Tproxy": Tproxy
        }

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall((json.dumps(payload) + "\n").encode())

        print(f"[EDGE_SERVER] Forwarded re-encrypted data to {dst_id}")


if __name__ == "__main__":
    km = KeyManager()
    km.get_reenc_key()
    reenc_key = km.reenc_key
    print(f"[EDGE_SERVER] Re-encryption Key: {reenc_key}")
    edge = EdgeServer(km.reenc_key)
    edge.start()