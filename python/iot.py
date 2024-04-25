import socket
import traceback
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST = "127.0.0.1"
PORT = 65439

BLOCK_SIZE = AES.block_size
MAX_RECV = 4028

KEY_ON_DEVICE = b"[0\xac\xd3\x00:\xbe\xd5\xf5\x9d\x9ed\xa1\xee\xc0D"


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


def three_way_handshake_reciever(conn, encrypter, decrypter):
    cmd_package = decrypter.decrypt(conn.recv(MAX_RECV))
    cmd = cmd_package[:len(cmd_package) - 16].decode()
    cmd_nx = cmd_package[len(cmd_package) - 16:]

    n2 = get_random_bytes(16)
    cmd_challenge_package = encrypter.encrypt(cmd_nx + n2)
    conn.sendall(cmd_challenge_package)

    n2x = decrypter.decrypt(conn.recv(16))
    if n2 != n2x:
        return "__error__"

    return cmd


def main():
    print("IOT Begin...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((HOST, PORT))

            # Setup server connection
            one_time_encrypter = AES.new(KEY_ON_DEVICE, AES.MODE_ECB)

            new_aes_key = get_random_bytes(16)
            n1 = get_random_bytes(16)
            server_aes_encrypter = AES.new(new_aes_key, AES.MODE_CTR, nonce=n1[:8])
            server_aes_decrypter = AES.new(new_aes_key, AES.MODE_CTR, nonce=n1[:8])
            conn.sendall(one_time_encrypter.encrypt(new_aes_key))
            conn.sendall(one_time_encrypter.encrypt(n1))
            n1x = server_aes_decrypter.decrypt(conn.recv(MAX_RECV))
            if n1 == n1x:
                print("IOT Accepts Server...")
            else:
                print("IOT Rejects Server.")
                raise Exception("IOT Rejects")

            while True:
                # Await CMD
                cmd = three_way_handshake_reciever(conn, server_aes_encrypter, server_aes_decrypter)
                if cmd == "__error__":
                    print(f"Receiving CMD failed")
                    break
                else:
                    print(f"Received CMD: {cmd}")

                if cmd == "exit":
                    break
                if len(cmd) == 0:
                    print("Server Disconnected.")
                    break

                # Send ACK of CMD; could be a blank message or data
                if three_way_handshake_instigate(conn, "ACK", server_aes_encrypter, server_aes_decrypter):
                    print(f"Ack Sent")
                else:
                    print(f"Sending Ack Failed")
                    break

            print("\n\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\nIOT Term")

        except BrokenPipeError or OSError:
            print(traceback.format_exc())
        finally:
            conn.close()


if __name__ == "__main__":
    main()
