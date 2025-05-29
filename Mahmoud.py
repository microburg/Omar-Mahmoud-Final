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

class StudentB:
    def __init__(self):
        self.student_name = "Mahmoud"
        self.port = 50002
        self.peer_port = 50001
        
        # Key file paths
        self.private_key_file = "mahmoud_private.pem"
        self.public_key_file = "mahmoud_public.pem"

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



        
        # Initialize socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        print(f"{self.student_name} initialized, connecting to Omar")
    
    def start_communication(self):
        # Connect to Omar's socket
        self.socket.connect(('localhost', self.peer_port))
        print(f"{self.student_name} connected to Omar")
        
        # Key exchange
        self.exchange_public_keys()
        self.establish_session_key(initiator=False)
        
        # Receive and send messages
        received = self.receive_secure_message()
        self.send_secure_message("Hello Omar, this is Mahmoud")
        
        # Receive and send student ID
        received = self.receive_secure_message()
        self.send_secure_message("My student ID is 202201930")
        
        # Close connection
        self.socket.close()

    def exchange_public_keys(self):
        # Send our public key
        public_key = self.rsa_key.publickey().export_key()
        self._send(public_key)
        
        # Receive Omar's public key
        peer_key = self._receive()
        self.peer_public_key = RSA.import_key(peer_key)
        print(f"{self.student_name} received Omar's public key")

    def establish_session_key(self, initiator=False):
        # Establish a shared session key using RSA key exchange
        if initiator:
            # As initiator, generate a random part and send it encrypted
            my_random = get_random_bytes(16)
            encrypted_random = self._rsa_encrypt(my_random)
            self._send(encrypted_random)

            # Receive Omar's random part
            peer_encrypted = self._receive()
            peer_random = self._rsa_decrypt(peer_encrypted)
            
            # Combine both random parts to create session key
            combined = my_random + peer_random
            self.session_key = hashlib.sha256(combined).digest()[:16]  # AES-128 key
        else:
            # As responder, receive first
            peer_encrypted = self._receive()
            peer_random = self._rsa_decrypt(peer_encrypted)
            
            # Generate our random part and send it
            my_random = get_random_bytes(16)
            encrypted_random = self._rsa_encrypt(my_random)
            self._send(encrypted_random)
            
            # Combine both random parts to create session key
            combined = peer_random + my_random
            self.session_key = hashlib.sha256(combined).digest()[:16]  # AES-128 key
        
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

    def _rsa_encrypt(self, data):
        # Encrypt data with Omar's public key
        cipher = PKCS1_OAEP.new(self.peer_public_key)
        return cipher.encrypt(data)
    
    def _rsa_decrypt(self, data):
        # Decrypt data with our private key
        cipher = PKCS1_OAEP.new(self.rsa_key)
        return cipher.decrypt(data)
    
    def _send(self, data):
        # Send data with length prefix
        if isinstance(data, str):
            data = data.encode()
        self.socket.send(len(data).to_bytes(4, 'big') + data)
    
    def _receive(self):
        # Receive data with length prefix
        length = int.from_bytes(self.socket.recv(4), 'big')
        return self.socket.recv(length)

if __name__ == "__main__":
    student_b = StudentB()
    student_b.start_communication()