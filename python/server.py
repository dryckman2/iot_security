import secrets
import socket
import traceback

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

SERVER_PRIVATE = RSA.importKey(
    """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDo8mtIodJtwTN14XBC8uNCmArG3uJtNASN+Kn2GsdjRJqEx1ED
nMCRFm9Z4ZEYtutQbHtwsqHuk+RGu92+mFs+mUBfll4FYmB4yaMmKw08Ho5IyJbp
cK9bV0Lb8Ff5Zr4KdUKVQDMDRiUYHf/OTiytI28dGhsh3HgTo5QkRkCgOwIDAQAB
AoGACNGMkC5YGgGTYiYLqu0o/09kMQ0lAz9R4NIGFSQEYlSpiNdG0N0xSQzRYFSy
un3KQLwqnCSXDsIYhTj9dwarhYuoWWt2qGjLp/taP4me8kb1g/aYO/KvWyR7ueSX
e3tBFwu94ppXs86/BT/ALZDV2lTQcc12mrwd/BltvkjPLBkCQQDzngtmucFgp/La
H/18Su2mQZl+ZrZUddC9bO8LxlIDNcORZy3hT+E2HlWvJvnFoAm3+h74Re5emqJQ
egOuKm1VAkEA9MmH5pRJBBZXMTeJRs11/81CoB7PB6jlHCu8XQykUgkFE26csYGb
xg+iQ1zFKFan5Bo66ssr/Onn1zGu0/1XTwJAH+e36Ik1WTpFpOmBojCR9S8sMhCz
mlYfs18741fiz8bPyRAxQwvaG+NXJ2w8U/SEsVKRkcRe1ob78Pw51Sp7TQJBAN2D
ifHE+pYySVEGermRsFh9vO79MkgyNLJbeaeSixiZhPhivnV7XiXLfAENcHTihifK
/MoAdZv3Z4+7LAQ2W80CQQCHlQOxpXl0CvEq1OXotw82L+8DQhaONz8VzF2JL/Yg
EhP//e4oJcBokB7A+unm2M/XYGLaKD+7wOV+dUr1oqfB
-----END RSA PRIVATE KEY-----"""
)

HOST = "127.0.0.1"
CLIENT_PORT = 65431
IOT_PORT = 65439

KEY_ON_DEVICE = b"[0\xac\xd3\x00:\xbe\xd5\xf5\x9d\x9ed\xa1\xee\xc0D"

BLOCK_SIZE = AES.block_size
MAX_RECV = 4028


def load_public_keys():
    server_pub_f = open("server_public.pem", "rb")
    client_pub_f = open("client_public.pem", "rb")
    server_pub_key = RSA.importKey(server_pub_f.read())
    client_pub_key = RSA.importKey(client_pub_f.read())

    return server_pub_key, client_pub_key


def setup_client_connection(conn, client_rsa_encryptor, server_rsa_decrypter):
    with conn:
        try:
            # Setup client connection
            msg = conn.recv(MAX_RECV)
            nx = server_rsa_decrypter.decrypt(msg)
            client_aes_key = get_random_bytes(16)
            client_aes_encrypt = AES.new(
                client_aes_key, AES.MODE_CTR, nonce=nx[:15]
            )  # AES using the first 16 bytes of n1 as nonce
            client_aes_decrypt = AES.new(
                client_aes_key, AES.MODE_CTR, nonce=nx[:15]
            )  # AES using the first 16 bytes of n1 as nonce
            conn.sendall(client_rsa_encryptor.encrypt(nx))

            msg = client_rsa_encryptor.encrypt(client_aes_key)
            conn.sendall(msg)
            conn.recv(0)
            n2 = get_random_bytes(16)
            conn.sendall(client_aes_encrypt.encrypt(n2))

            n2x = client_aes_decrypt.decrypt(conn.recv(MAX_RECV))
            if n2 == n2x:
                print("Server Accepts Client...")
            else:
                print(f"{n2=}")
                print(f"{n2x=}")
                print("Server Rejects Client.")
                raise Exception("Server Rejects")

        except Exception as e:
            conn.close()
            print(traceback.format_exc())


def setup_iot_conn(conn: socket):
    one_time_decrypt = AES.new(KEY_ON_DEVICE, AES.MODE_ECB)
    iot_aes_key = one_time_decrypt.decrypt(conn.recv(16))
    n1x = one_time_decrypt.decrypt(conn.recv(16))
    iot_aes_encrypter = AES.new(iot_aes_key, AES.MODE_CTR, nonce=n1x[:15])
    iot_aes_decrypter = AES.new(iot_aes_key, AES.MODE_CTR, nonce=n1x[:15])
    conn.sendall(iot_aes_encrypter.encrypt(n1x))
    print("Server Accepts IOT...")


def main():
    print("Server Begin...")
    server_public, client_public = load_public_keys()

    client_rsa_encryptor = PKCS1_OAEP.new(client_public)
    server_rsa_decrypter = PKCS1_OAEP.new(SERVER_PRIVATE)

    # Client Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, CLIENT_PORT))
        s.listen()
        client_conn, add = s.accept()
        print("Client Found...")
        setup_client_connection(client_conn, client_rsa_encryptor, server_rsa_decrypter)

        # Once Client is setup start IOT socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.bind((HOST, IOT_PORT))
            s2.listen()
            iot_conn, add = s2.accept()
            print("IOT Found...")
            setup_iot_conn(iot_conn)

            client_conn.close()
            iot_conn.close()

            print("\n\n-=-=-=-=-=-=-=-=-=-=-=-=-\nServer Term")


if __name__ == "__main__":
    main()
