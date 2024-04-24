import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CLIENT_PRIVATE = RSA.importKey("""-----BEGIN RSA PRIVATE KEY-----
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
    print("Client Begin...")
    server_public, client_public = load_public_keys()

    client_rsa_decrypter = PKCS1_OAEP.new(CLIENT_PRIVATE)
    server_rsa_encrypter = PKCS1_OAEP.new(server_public)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Receive encrypted information from host
        enc_aes_key = s.recv(1024)
        server_aes_nonce_enc = s.recv(1024)
        print("AES Key Received")

        # Use information to create aes encrypter and decrypter
        aes_key = client_rsa_decrypter.decrypt(enc_aes_key)
        aes_cipher_enc = AES.new(aes_key, AES.MODE_CTR)
        server_aes_nonce = client_rsa_decrypter.decrypt(server_aes_nonce_enc)
        aes_cipher_denc = AES.new(aes_key, AES.MODE_CTR,
                                  nonce=server_aes_nonce)

        # Send client encrypted nonce to server for decoding
        nonce = aes_cipher_enc.nonce
        enc_nonce = server_rsa_encrypter.encrypt(nonce)
        s.sendall(enc_nonce)

        print("Messages\n-------------------------------------")
        while True:
            message = input("You: ")
            enc_message = aes_cipher_enc.encrypt(pad(message.encode(), AES.block_size))
            s.sendall(enc_message)
            enc_server_message = s.recv(1024)  # Await response
            server_message = unpad(aes_cipher_denc.decrypt(enc_server_message), AES.block_size).decode()
            print(f"Server: {server_message}")


if __name__ == "__main__":
    main()