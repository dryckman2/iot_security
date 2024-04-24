import secrets
import socket
import traceback
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CLIENT_PRIVATE = RSA.importKey(
    """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCeg9uNM3cb1Z1kidvG+OoyO2SzdbCpQmKlWEbi4HRADzQnRLy3
9TWBr/QQ///oVZT/sLhBArmHEN7U1Hm+pk/uvnvndDdbkeZ95HmhekT/Gcs5JIDB
ehkoI+Nh4k10zf6XqBO34XpnUB6KN44S5b9o1SFKstwYpC4XAoVXEOGh8QIDAQAB
AoGAAlAZuMB2vTL7ei9Rw+A3aJa5xC2UL5AOqOt2E1Ljl1ixcd48o7GB/5ut476c
gQsYord1JMuxodEi8zeLdDbwhR0dDrFKQyoYJe7MzeQzGiCLtAYp/l9PoAAKDbn+
JXKwOKhb3T6GtTybMlRsgC2/yYhGxLMLyIlsIvn+fhYvN5ECQQC1zt+iWgZ79zi/
Cd1uEgmXU0tMlVc9aQtoz84Icct6ep29ym6ZBOJjizckDV/qcszqutjxaqsu+2xo
1qd4f0L5AkEA3zObo0tw91TtN3GWq1sYaBPJM86gTOKgZruQFzLAMWdfSjA6QOiy
9Bba+ZR7f47tJjhnf5cnINJzaqPjjQ8cuQJBAIlJ88Q0eSsJb/eK6oQg6M813emx
6FP+S9hU+7+SttYBW7ai88tnTdFfoj7+PozbLfSfLg13wFbVE3NDjOlIKHkCQHNT
MQmQg0/oG6FYGWd0bAnqnz0beAwB1KsAIpU57cAZD00/2fmLwlsILCBkreLcsH/d
CO0N5nO5CVWCVKKfulECQQCuuQped0DjsO5EH4bTonEzObwVj+Kz001P5XjLyS7o
e9GWjgcXvt8n8qLUnLMw4dc0/BXlBO3RIteM5kOLpwBK
-----END RSA PRIVATE KEY-----"""
)

HOST = "127.0.0.1"
PORT = 65431

BLOCK_SIZE = AES.block_size
MAX_RECV = 4028


def load_public_keys():
    server_pub_f = open("server_public.pem", "rb")
    client_pub_f = open("client_public.pem", "rb")
    server_pub_key = RSA.importKey(server_pub_f.read())
    client_pub_key = RSA.importKey(client_pub_f.read())

    return server_pub_key, client_pub_key


def main():
    print("Client Begin...")
    server_public, client_public = load_public_keys()

    client_rsa_decrypter = PKCS1_OAEP.new(CLIENT_PRIVATE)
    server_rsa_encrypter = PKCS1_OAEP.new(server_public)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((HOST, PORT))

            # Setup server connection
            n1 = secrets.token_urlsafe(16)
            conn.sendall(server_rsa_encrypter.encrypt(n1.encode()))

            n1x = client_rsa_decrypter.decrypt(conn.recv(MAX_RECV)).decode()
            if n1 == n1x:
                print("Client Accepts Server...")
            else:
                print("Client Rejects Server.")
                raise Exception("Client Rejects")

            enc_server_key = conn.recv(128)  # Receive just key
            server_aes_key = client_rsa_decrypter.decrypt(enc_server_key)
            server_aes_encrypter = AES.new(
                server_aes_key, AES.MODE_CTR, nonce=n1.encode()[:15]
            )
            server_aes_decrypter = AES.new(
                server_aes_key, AES.MODE_CTR, nonce=n1.encode()[:15]
            )
            n2 = server_aes_encrypter.encrypt(
                server_aes_decrypter.decrypt(conn.recv(MAX_RECV))
            )
            conn.sendall(n2)

            print("\n\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\nClient Term")

        except Exception as e:
            print(traceback.format_exc())
        finally:
            conn.close()


if __name__ == "__main__":
    main()
