import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
import hashlib
import json
import base64
import os

class StudentA:
    def __init__(self):
        self.student_name = "Omar"
        self.port = 50001
        self.peer_port = 50002

        # Key file paths
        self.private_key_file = "omar_private.pem"
        self.public_key_file = "omar_public.pem"

        # Load or generate RSA keys
        if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
            with open(self.private_key_file, "rb") as f:
                self.rsa_key = RSA.import_key(f.read())
        else:
            self.rsa_key = RSA.generate(2048)
            with open(self.private_key_file, "wb") as f:
                f.write(self.rsa_key.export_key())
            with open(self.public_key_file, "wb") as f:
                f.write(self.rsa_key.publickey().export_key())

        self.peer_public_key = None
        self.session_key = None
        
        # Initialize socket conncection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('localhost', self.port))
        self.socket.listen(1)
        
        print(f"{self.student_name} on port {self.port}")
    
    def start_communication(self):
        # Wait for connection from Student B
        self.connection, _ = self.socket.accept()
        print(f"{self.student_name} connected to Mahmoud")
        
        # Change the keuys
        self.exchange_public_keys()
        self.establish_session_key(initiator=True)
        
        # Send messages
        self.send_secure_message("Hello Mahmoud, i am Omar")
        received = self.receive_secure_message()
        
        # Send the student ID
        self.send_secure_message("My student ID is 202201120")
        received = self.receive_secure_message()

        # Close connection
        self.connection.close()
        self.socket.close()

    def exchange_public_keys(self):
        # Send our public key
        public_key = self.rsa_key.publickey().export_key()
        self._send(public_key)

        # Receive Mahmoud public key
        peer_key = self._receive()
        self.peer_public_key = RSA.import_key(peer_key)
        print(f"{self.student_name} received Mahmoud public key")

    def establish_session_key(self, initiator=False):
        if initiator:
            # generate a random part and send it encrypted
            my_random = get_random_bytes(16) # make a 128 bit by random
            encrypted_random = self._rsa_encrypt(my_random)
            self._send(encrypted_random)
            
            # Receive Mahmoud random part
            peer_encrypted = self._receive()
            peer_random = self._rsa_decrypt(peer_encrypted)
            
            # Combine both random parts to create session key
            combined = my_random + peer_random
            # Here we Want only the first 128 so we exclude the rest
            self.session_key = hashlib.sha256(combined).digest()[:16]
        
        print(f"{self.student_name} established session key: {self.session_key.hex()}")

    def send_secure_message(self, message):
        # Encrypt with AES
        cipher = AES.new(self.session_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        
        # Sign the original message
        h = SHA256.new(message.encode())
        signature = pkcs1_15.new(self.rsa_key).sign(h)
        
        # Prepare package
        package = {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'signature': base64.b64encode(signature).decode()
        }
        
        self._send(json.dumps(package).encode())
        print(f"{self.student_name} sent encrypted message: {message}")

    def receive_secure_message(self):
        # Receive package
        package = json.loads(self._receive().decode())
        
        # Decrypt
        nonce = base64.b64decode(package['nonce'])
        ciphertext = base64.b64decode(package['ciphertext'])
        tag = base64.b64decode(package['tag'])
        
        cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Verify signature
        h = SHA256.new(plaintext)
        signature = base64.b64decode(package['signature'])
        try:
            pkcs1_15.new(self.peer_public_key).verify(h, signature)
            print(f"{self.student_name} received and verified message: {plaintext.decode()}")
            return plaintext.decode()
        except (ValueError, TypeError):
            print("Signature verification failed!")
            return None

    # encrypt using mahmoud public key
    def _rsa_encrypt(self, data):
        cipher = PKCS1_OAEP.new(self.peer_public_key)
        return cipher.encrypt(data)
    
    # decrypt using our private key
    def _rsa_decrypt(self, data):
        cipher = PKCS1_OAEP.new(self.rsa_key)
        return cipher.decrypt(data)
    
    #send and receive data with length prefix
    def _send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.connection.send(len(data).to_bytes(4, 'big') + data)
    
    def _receive(self):
        length = int.from_bytes(self.connection.recv(4), 'big')
        return self.connection.recv(length)

if __name__ == "__main__":
    student_a = StudentA()
    student_a.start_communication()