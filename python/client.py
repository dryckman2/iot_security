import socket
import traceback
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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

MAX_RECV = 4028


def load_public_keys():
    server_pub_f = open("server_public.pem", "rb")
    client_pub_f = open("client_public.pem", "rb")
    server_pub_key = RSA.importKey(server_pub_f.read())
    client_pub_key = RSA.importKey(client_pub_f.read())

    return server_pub_key, client_pub_key


def three_way_handshake_instigate(conn, msg, encrypter, decrypter):
    msg_nonce = get_random_bytes(16)
    msg_package = encrypter.encrypt(msg.encode() + msg_nonce)
    conn.sendall(msg_package)

    msg_challenge_packet = decrypter.decrypt(conn.recv(16 * 2))
    nx = msg_challenge_packet[:16]
    n2x = msg_challenge_packet[16:]
    if nx != msg_nonce:
        return False
    conn.sendall(encrypter.encrypt(n2x))
    return True


def three_way_handshake_receiver(conn, encrypter, decrypter):
    cmd_package = decrypter.decrypt(conn.recv(MAX_RECV))
    cmd = cmd_package[: len(cmd_package) - 16].decode()
    cmd_nx = cmd_package[len(cmd_package) - 16 :]

    n2 = get_random_bytes(16)
    cmd_challenge_package = encrypter.encrypt(cmd_nx + n2)
    conn.sendall(cmd_challenge_package)

    n2x = decrypter.decrypt(conn.recv(16))
    if n2 != n2x:
        return "__error__"

    return cmd


def main():
    print("Client Begin...")
    server_public, client_public = load_public_keys()

    client_rsa_decrypter = PKCS1_OAEP.new(CLIENT_PRIVATE)
    server_rsa_encrypter = PKCS1_OAEP.new(server_public)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((HOST, PORT))

            # Setup server connection
            n1 = get_random_bytes(16)
            conn.sendall(server_rsa_encrypter.encrypt(n1))

            n1x = client_rsa_decrypter.decrypt(conn.recv(MAX_RECV))
            if n1 == n1x:
                print("Client Accepts Server...")
            else:
                print("Client Rejects Server.")
                raise Exception("Client Rejects")

            enc_server_key = conn.recv(128)  # Receive just key
            server_aes_key = client_rsa_decrypter.decrypt(enc_server_key)
            server_aes_encrypter = AES.new(server_aes_key, AES.MODE_CTR, nonce=n1[:8])
            server_aes_decrypter = AES.new(server_aes_key, AES.MODE_CTR, nonce=n1[:8])
            n2 = server_aes_encrypter.encrypt(
                server_aes_decrypter.decrypt(conn.recv(MAX_RECV))
            )
            conn.sendall(n2)

            # Sample Command Interface
            while True:
                print()  # Make space for readability

                # Send Command
                cmd = input("Input Command: ").strip()
                if three_way_handshake_instigate(
                    conn, cmd, server_aes_encrypter, server_aes_decrypter
                ):
                    print(f"Command Sent!")
                else:
                    print(f"Sending Failed")
                    break

                if cmd == "exit":
                    break
                if len(cmd.encode()) == 0:
                    print("Server Disconnected.")
                    break

                # Await Ack Message
                response = three_way_handshake_receiver(
                    conn, server_aes_encrypter, server_aes_decrypter
                )
                if response == "__error__":
                    print(f"Receiving ACK failed")
                    break
                else:
                    print(f"Received ACK")

            print("\n\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\nClient Term")

        except BrokenPipeError or OSError:
            print(traceback.format_exc())
        finally:
            conn.close()


if __name__ == "__main__":
    main()
