import socket
import traceback
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


HOST = "127.0.0.1"
PORT = 65439

BLOCK_SIZE = AES.block_size
MAX_RECV = 4028

KEY_ON_DEVICE = b"[0\xac\xd3\x00:\xbe\xd5\xf5\x9d\x9ed\xa1\xee\xc0D"


def main():
    print("IOT Begin...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((HOST, PORT))

            # Setup server connection
            one_time_encrypter = AES.new(KEY_ON_DEVICE, AES.MODE_ECB)

            new_aes_key = get_random_bytes(16)
            n1 = get_random_bytes(16)
            server_aes_encrypter = AES.new(new_aes_key, AES.MODE_CTR, nonce=n1[:15])
            server_aes_decrypter = AES.new(new_aes_key, AES.MODE_CTR, nonce=n1[:15])
            conn.sendall(one_time_encrypter.encrypt(new_aes_key))
            conn.sendall(one_time_encrypter.encrypt(n1))
            n1x = server_aes_decrypter.decrypt(conn.recv(MAX_RECV))
            if n1 == n1x:
                print("IOT Accepts Server...")
            else:
                print(n1)
                print(n1x)
                print("IOT Rejects Server.")
                raise Exception("IOT Rejects")

            # (* IOT will create IOTServerKey here. It is passed in so we can query it*)
            # new N1 : nonce;
            # out(c,aes_enc(((key_to_bitstring(IOTServerKey),nonce_to_bitstring(N1))),keyOnDevice));
            # in(c,enc_msg_verification:bitstring);
            # if N1 = bitstring_to_nonce(aes_dec(enc_msg_verification,IOTServerKey)) then
            # event IOTAccepts(IOTServerKey,N1);

            print("\n\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\nIOT Term")

        except Exception as e:
            print(traceback.format_exc())
        finally:
            conn.close()


if __name__ == "__main__":
    main()
