# Lab04Final -- Part 3: The Stateful Interceptor
# DH key exchange + a rollback-resistant PRNG stream cipher + Mallory as an
# active MITM. (Same template as the old Lab03DHProgram.py, renamed and
# refiled under Lab04Final -- Lab03's schemes/DH content now lives here.)

import hashlib
import secrets
import os



# --- UI HELPER FUNCTIONS ---
def print_header(text):
    print(f"\n{'='*60}\n{text}\n{'='*60}")

def print_step(text):
    print(f"\n>> {text}")

def print_info(label, value):
    print(f"   [{label}]: {str(value)[:70]}...")



# --- Define Diffie-Hellman Constants G and P ---

P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

G = 2



# --- PART A: STATEFUL PRNG ---

# Implement logic for PRNG function here
class SecurePRNG:

    def __init__(self, seed_int):
        self.init(seed_int)

    def init(self, seed_int):
        """Hash the DH shared secret into a fixed-size 32-byte state."""
        seed_bytes = seed_int.to_bytes(max(1, (seed_int.bit_length() + 7) // 8), "big")
        self.state = hashlib.sha256(b"Lab04 SecurePRNG init\x00" + seed_bytes).digest()

    def generate(self, n_bytes):
        if n_bytes < 0:
            raise ValueError("n_bytes must be non-negative")

        output = b""
        while len(output) < n_bytes:
            output += hashlib.sha256(b"Lab04 SecurePRNG output\x00" + self.state).digest()
            self.state = hashlib.sha256(b"Lab04 SecurePRNG update\x00" + self.state).digest()

        return output[:n_bytes]



def stream_cipher(data, prng):
    keystream = prng.generate(len(data))
    return bytes(value ^ key for value, key in zip(data, keystream))


def xor_crypt(data, prng):
    """Compatibility name used by the provided simulation code."""
    return stream_cipher(data, prng)



# --- PART B: COMMUNICATION PROTOCOL ---

class Entity:
    def __init__(self, name):
        self.name = name
        self.init()

    def init(self):
        self.private_key = secrets.randbelow(P - 3) + 2
        self.public_key = pow(G, self.private_key, P)
        self.session_prng = None

    def get_public_hex(self):
        return hex(self.public_key)
    
    def establish_session(self, partner_pub_hex):
        partner_pub = int(partner_pub_hex, 16)
        shared_secret = pow(partner_pub, self.private_key, P)
        self.session_prng = SecurePRNG(shared_secret)



# --- DO NOT MODIFY THIS CLASS --- #
# This class simulates the network and allows for an interceptor 'hook' (Mallory) to manipulate messages in transit.
class Network:
    def __init__(self):
        self.mallory = None  # The interceptor 'hook'

    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload



# --- PART C: THE MALLORY MITM PROXY ---

# Implement logic for Mallory
class Mallory:
    def __init__(self):
        self.init()

    def init(self):
        self.private_key = secrets.randbelow(P - 3) + 2
        self.public_key = pow(G, self.private_key, P)
        self.public_hex = hex(self.public_key)
        # Mallory maintains TWO sessions
        self.alice_prng = None
        self.bob_prng = None
        self.alice_public_key = None
        self.bob_public_key = None

    def intercept(self, sender, recipient, payload):
        # 1. Implement Logic for Key Exchange Interception
        if isinstance(payload, str) and payload.startswith("0x"):
            remote_pub = int(payload, 16)
            my_shared_secret = pow(remote_pub, self.private_key, P)

            if sender.lower() == "alice":
                self.alice_public_key = remote_pub
                self.alice_prng = SecurePRNG(my_shared_secret)
            elif sender.lower() == "bob":
                self.bob_public_key = remote_pub
                self.bob_prng = SecurePRNG(my_shared_secret)
    
            return self.public_hex # Return Mallory's key instead to generate session PRNGs with Alice and Bob
        
        # 2. Implement Logic for Message Interception/Modification
        if isinstance(payload, bytes):
            print(f"[MALLORY] Intercepting Encrypted Message from {sender}...")

            if sender.lower() == "alice":
                sender_prng, recipient_prng = self.alice_prng, self.bob_prng
            elif sender.lower() == "bob":
                sender_prng, recipient_prng = self.bob_prng, self.alice_prng
            else:
                return payload

            if sender_prng is None or recipient_prng is None:
                raise RuntimeError("Mallory intercepted a message before both sessions were established")

            plaintext = xor_crypt(payload, sender_prng)
            print(f"[MALLORY] Read plaintext: {plaintext.decode(errors='replace')}")

            if b"9pm" in plaintext:
                modified_plaintext = plaintext.replace(b"9pm", b"3am", 1)
            else:
                words = plaintext.split()
                if words:
                    words[0] = b"COMPROMISED"
                    modified_plaintext = b" ".join(words)
                else:
                    modified_plaintext = b"!"

            print(f"[MALLORY] Modified plaintext: {modified_plaintext.decode(errors='replace')}")
            return xor_crypt(modified_plaintext, recipient_prng)

        return payload



# --- DO NOT MODIFY THIS FUNCTION --- #
# --- MAIN EXECUTION SIMULATION ---
def main():
    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")
    
    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()
    
    # Display Group Parameters
    print_step("Step 0: Global Group Parameters")
    print_info("G (Generator)", G)
    print_info("P (Prime)", P)

    print_step("Step 1: Public Key Exchange")
    print_info("Alice Private (a)", alice.private_key)
    print_info("Bob Private (b)", bob.private_key)
    
    # Alice -> Bob
    alice_pub = alice.get_public_hex()
    print_info("Alice Public (A = G^a mod P)", alice_pub)
    key_for_bob = net.send("Alice", "Bob", alice_pub)
    
    # Bob -> Alice
    bob_pub = bob.get_public_hex()
    print_info("Bob Public (B = G^b mod P)", bob_pub)
    key_for_alice = net.send("Bob", "Alice", bob_pub)
    
    print_step("Step 2: Establishing Sessions")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    print("   [Status]: Shared Secret computed: S = B^a mod P = A^b mod P")
    
    print_step("Step 3: Secure Message Transmission")
    message = b"The quick brown fox jumps over the lazy dog."
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng)
    
    print_info("Bob decrypted", final_message.decode())

    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")
    
    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory
    
    print_step("Step 1: Mallory's Parameters")
    print_info("Mallory Private (m)", mallory.private_key)
    print_info("Mallory Public (M)", mallory.public_hex)

    print_step("Step 2: Compromised Key Exchange")
    # Alice sends A -> Mallory Intercepts -> Returns M to Alice
    # Bob sends B -> Mallory Intercepts -> Returns M to Bob
    print("Alice sending key to Bob...")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())
    
    print("Bob sending key to Alice...")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())
    
    print_step("Step 3: Poisoned Shared Secrets")
    alice.establish_session(key_for_alice)
    bob.establish_session(key_for_bob)
    
    # Note: Alice's session uses S1 = M^a, Bob's uses S2 = M^b. Mallory knows both.
    print("   [Alice Session]: S_am = (Mallory_Pub)^a mod P")
    print("   [Bob Session]:   S_bm = (Mallory_Pub)^b mod P")

    print_step("Step 4: Interception")
    message = b"Meet me at 9pm."
    encrypted_msg = xor_crypt(message, alice.session_prng)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    
    final_message = xor_crypt(delivered_data, bob.session_prng)
    print_info("Bob received", final_message.decode())
    
    if b"3am" in final_message:
        print("\n[DANGER] MITM SUCCESS: Mallory used her private key (m) to decrypt and re-encrypt.")

if __name__ == "__main__":
    main()
