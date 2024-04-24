import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SERVER_PRIVATE = RSA.importKey("""-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----""")

HOST = "127.0.0.1"
PORT = 65432


def load_public_keys():
    server_pub_f = open('server_public.pem', 'rb')
    client_pub_f = open('client_public.pem', 'rb')
    server_pub_key = RSA.importKey(server_pub_f.read())
    client_pub_key = RSA.importKey(client_pub_f.read())

    return server_pub_key, client_pub_key


def main():
    print("Server Begin...")
    server_public, client_public = load_public_keys()

    client_rsa_encryptor = PKCS1_OAEP.new(client_public)
    server_rsa_decrypter = PKCS1_OAEP.new(SERVER_PRIVATE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, add = s.accept()
        print("Client Found")
        with conn:
            while True:
                # Generate New aes Key and Nonce
                aes_key = get_random_bytes(16)
                aes_cipher_enc = AES.new(aes_key, AES.MODE_CTR)
                nonce = aes_cipher_enc.nonce

                # Encrypt aes Key and Nonce with RSA
                enc_aes_key = client_rsa_encryptor.encrypt(aes_key)
                enc_nonce = client_rsa_encryptor.encrypt(nonce)

                # Send to client
                conn.sendall(enc_aes_key)
                conn.sendall(enc_nonce)

                # Receive client's nonce
                client_aes_nonce_enc = conn.recv(1024)

                # Use decrypted nonce to make a decrypter for client messages
                client_aes_nonce = server_rsa_decrypter.decrypt(client_aes_nonce_enc)
                aes_cipher_denc = AES.new(aes_key, AES.MODE_CTR,
                                          nonce=client_aes_nonce)
                print("Messages\n-------------------------------------")
                while True:
                    enc_client_message = conn.recv(1024)  # Await response
                    if not enc_client_message:
                        # Client Left
                        break
                    client_message = unpad(aes_cipher_denc.decrypt(enc_client_message), AES.block_size).decode()
                    print(f"Client: {client_message}")
                    message = input("You: ")
                    enc_message = aes_cipher_enc.encrypt(pad(message.encode(), AES.block_size))
                    conn.sendall(enc_message)


if __name__ == "__main__":
    main()