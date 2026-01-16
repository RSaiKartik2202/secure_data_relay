from fastecdsa.curve import secp256k1
import secrets
import socket
import json

class TA:
    def __init__(self):
        self.curve = secp256k1
        self.P = self.curve.G          # Generator point
        self.q = self.curve.q          # Curve order

    def generate_key_pair_orig(self):
        """
        Generates a public-private key pair for data originator digital twin.
        """
        sk_org = secrets.randbelow(self.q-1) + 1
        pk_org = sk_org * self.P
        return sk_org, pk_org

    def generate_key_edge(self, sk_org, sk_dst):
        """
        Generates a unidirectional re-encryption key for the edge server.
        """
        sk_org_inv= pow(sk_org, -1, self.q)
        reenc_key = (sk_org_inv * sk_dst) % self.q

        return reenc_key

    def generate_key_pair_dest(self):
        """
        Generates a public-private key pair for data destination digital twin.
        """
        sk_dst = secrets.randbelow(self.q-1) + 1
        pk_dst = sk_dst * self.P
        return sk_dst, pk_dst

    def send_keys(self, key_json, recipient_port):
        """
        Sends the generated keys to the specified recipient.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("localhost", recipient_port))
            s.sendall((json.dumps(key_json) + "\n").encode())
            print(f"[TA] Keys sent to port {recipient_port}")
        except ConnectionRefusedError:
            print(f"[TA] Could not connect to port {recipient_port}")
        finally:
            s.close()
        
        

if __name__ == "__main__":
    ta = TA()
    sk_org, pk_org = ta.generate_key_pair_orig()
    sk_dst, pk_dst = ta.generate_key_pair_dest()
    reenc_key = ta.generate_key_edge(sk_org, sk_dst)

    org_keys = {
        "curve": "secp256k1",
        "sk_org": sk_org,
        "pk_org": {
            "x": pk_org.x,
            "y": pk_org.y
        }
    }
    ta.send_keys(org_keys, 8081)

    dst_keys = {
        "curve": "secp256k1",
        "sk_dst": sk_dst,
        "pk_dst": {
            "x": pk_dst.x,
            "y": pk_dst.y
        }
    }
    ta.send_keys(dst_keys, 8082)

    edge_key = {
        "reenc_key": reenc_key
    }
    ta.send_keys(edge_key, 8083)