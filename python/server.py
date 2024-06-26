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


def setup_client_connection(conn, client_rsa_encryptor, server_rsa_decrypter):
    try:
        # Setup client connection
        msg = conn.recv(MAX_RECV)
        nx = server_rsa_decrypter.decrypt(msg)
        client_aes_key = get_random_bytes(16)
        client_aes_encrypt = AES.new(
            client_aes_key, AES.MODE_CTR, nonce=nx[:8]
        )  # AES using the first 16 bytes of n1 as nonce
        client_aes_decrypt = AES.new(
            client_aes_key, AES.MODE_CTR, nonce=nx[:8]
        )  # AES using the first 16 bytes of n1 as nonce
        conn.sendall(client_rsa_encryptor.encrypt(nx))

        msg = client_rsa_encryptor.encrypt(client_aes_key)
        conn.sendall(msg)
        n2 = get_random_bytes(16)
        conn.sendall(client_aes_encrypt.encrypt(n2))

        n2x = client_aes_decrypt.decrypt(conn.recv(MAX_RECV))
        if n2 == n2x:
            print("Server Accepts Client...")
        else:
            print("Server Rejects Client.")
            raise Exception("Server Rejects")

        return client_aes_encrypt, client_aes_decrypt

    except BrokenPipeError or OSError:
        conn.close()
        print(traceback.format_exc())


def setup_iot_conn(conn: socket):
    iot_id_raw = conn.recv(4)
    iot_id = "".join(format(x, "02x") for x in iot_id_raw)
    one_time_decrypt = AES.new(KEY_ON_DEVICE, AES.MODE_ECB)
    iot_aes_key = one_time_decrypt.decrypt(conn.recv(16))
    n1x = one_time_decrypt.decrypt(conn.recv(16))
    iot_aes_encrypter = AES.new(iot_aes_key, AES.MODE_CTR, nonce=n1x[:8])
    iot_aes_decrypter = AES.new(iot_aes_key, AES.MODE_CTR, nonce=n1x[:8])
    conn.sendall(iot_aes_encrypter.encrypt(n1x))
    print(f"Server Accepts IO: 0x{iot_id}...")
    return iot_aes_encrypter, iot_aes_decrypter, iot_id


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
        client_encrypter, client_decrypter = setup_client_connection(
            client_conn, client_rsa_encryptor, server_rsa_decrypter
        )

        # Once Client is set up start IOT socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
            s2.bind((HOST, IOT_PORT))
            s2.listen()
            iot_conn, add = s2.accept()
            print("IOT Found...")
            iot_encrypter, iot_decrypter, iot_id = setup_iot_conn(iot_conn)

            while True:
                print()  # Make space for readability

                # Await Command
                cmd = three_way_handshake_receiver(
                    client_conn, client_encrypter, client_decrypter
                )
                if cmd == "__error__":
                    print(f"Receiving CMD failed")
                    break
                else:
                    print(f"Received CMD: {cmd}")

                # Forward Command To IOT
                if three_way_handshake_instigate(
                    iot_conn, cmd, iot_encrypter, iot_decrypter
                ):
                    print(f"Forwarding CMD to IOT: 0x{iot_id}")
                else:
                    print(f"Sending Failed")
                    break

                if cmd == "exit":
                    break
                if len(cmd) == 0:
                    print("Client Disconnected.")
                    break

                # Await Ack Message
                response = three_way_handshake_receiver(
                    iot_conn, iot_encrypter, iot_decrypter
                )
                if response == "__error__":
                    print(f"Receiving ACK failed")
                    break
                else:
                    print(f"Received ACK from IOT:{iot_id}")

                # Forward Ack To Client
                if three_way_handshake_instigate(
                    client_conn, response, client_encrypter, client_decrypter
                ):
                    print(f"Forwarding ACK")
                else:
                    print(f"Sending Failed")
                    break

            client_conn.close()
            iot_conn.close()

            print("\n\n-=-=-=-=-=-=-=-=-=-=-=-=-\nServer Term")


if __name__ == "__main__":
    main()
