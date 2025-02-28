import asyncio
from typing import Dict, List, Tuple, Any

from nacl.signing import SigningKey

# Import the simplified SIGMA implementation
from user import (
    User, 
    PydanticSigningKey, 
    PydanticVerifyKey,
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3
)

# Import the necessary CA classes
from sigma.ca import Certificate, CertificateAuthority


# ------------------------------------------------------------------------------
# Simple Network Simulation
# ------------------------------------------------------------------------------

class SimpleNetwork:
    """A simple network simulator for the SIGMA protocol."""
    
    def __init__(self):
        self.message_queues: Dict[str, List[Tuple[str, Any]]] = {}
        
    def register_user(self, user_id: str):
        """Register a user with the network."""
        if user_id not in self.message_queues:
            self.message_queues[user_id] = []
    
    def send_message(self, sender: str, recipient: str, message: Any):
        """Send a message from sender to recipient."""
        print(f"{sender} → {recipient}: {message.__class__.__name__}")
        if recipient not in self.message_queues:
            raise ValueError(f"Unknown recipient: {recipient}")
        self.message_queues[recipient].append((sender, message))
    
    def send_encrypted(self, sender: str, recipient: str, encrypted: bytes):
        """Send an encrypted application message."""
        print(f"{sender} → {recipient}: Encrypted message ({len(encrypted)} bytes)")
        if recipient not in self.message_queues:
            raise ValueError(f"Unknown recipient: {recipient}")
        self.message_queues[recipient].append((sender, encrypted))
    
    def has_messages(self, user_id: str) -> bool:
        """Check if a user has messages waiting."""
        return len(self.message_queues.get(user_id, [])) > 0
    
    def get_next_message(self, user_id: str) -> Tuple[str, Any]:
        """Get the next message for a user."""
        if not self.has_messages(user_id):
            raise ValueError(f"No messages for user: {user_id}")
        return self.message_queues[user_id].pop(0)


# ------------------------------------------------------------------------------
# Demo Functions
# ------------------------------------------------------------------------------

async def setup_users():
    """Set up a certificate authority and two users."""
    # Create a Certificate Authority
    ca_signing_key = SigningKey.generate()
    ca = CertificateAuthority(
        signing_key=ca_signing_key
    )
    
    # Create a network
    network = SimpleNetwork()
    
    # Create Alice
    alice_signing_key = PydanticSigningKey.generate()
    alice_verify_key = PydanticVerifyKey(alice_signing_key.verify_key.encode())
    alice = User(
        identity="alice",
        ca=ca,
        signing_key=alice_signing_key,
        verify_key=alice_verify_key,
        network=network
    )
    network.register_user("alice")
    
    # Create Bob
    bob_signing_key = PydanticSigningKey.generate()
    bob_verify_key = PydanticVerifyKey(bob_signing_key.verify_key.encode())
    bob = User(
        identity="bob",
        ca=ca,
        signing_key=bob_signing_key,
        verify_key=bob_verify_key,
        network=network
    )
    network.register_user("bob")
    
    return alice, bob, network


async def run_handshake(alice_user: User, bob_user: User, network: SimpleNetwork):
    """Run the SIGMA handshake between Alice and Bob."""
    print("\n=== Obtaining Certificates ===")
    
    # Both users obtain certificates
    alice_verified = alice_user.obtain_certificate()
    print("Alice obtained certificate")
    
    bob_verified = bob_user.obtain_certificate()
    print("Bob obtained certificate")
    
    print("\n=== Starting Handshake: Alice initiates, Bob responds ===")
    
    # Alice initiates
    alice_initiator = alice_verified.initiate_handshake("bob")
    msg1, alice_waiting = alice_initiator.send_message1()
    print("Alice sent Message 1 to Bob")
    
    # Bob waits for handshake
    bob_responder = bob_verified.wait_for_handshake("alice")
    
    # Process message 1
    sender, message = network.get_next_message("bob")
    assert sender == "alice" and isinstance(message, SigmaMessage1)
    msg2, bob_waiting = bob_responder.receive_message1(message)
    print("Bob received Message 1, sent Message 2 to Alice")
    
    # Process message 2
    sender, message = network.get_next_message("alice")
    assert sender == "bob" and isinstance(message, SigmaMessage2)
    msg3, alice_ready = alice_waiting.receive_message2(message)
    print("Alice received Message 2, sent Message 3 to Bob")
    
    # Process message 3
    sender, message = network.get_next_message("bob")
    assert sender == "alice" and isinstance(message, SigmaMessage3)
    bob_ready = bob_waiting.receive_message3(message)
    print("Bob received Message 3, handshake complete")
    
    print("\n=== Secure Communication ===")
    
    # Now Alice and Bob can communicate securely
    alice_ready.send_secure_message(b"Hello Bob, this is a secure message!")
    print("Alice sent secure message to Bob")
    
    # Bob receives the message
    sender, encrypted_msg = network.get_next_message("bob")
    decrypted = bob_ready.receive_secure_message(encrypted_msg)
    print(f"Bob received and decrypted: {decrypted.decode()}")
    
    # Bob replies
    bob_ready.send_secure_message(b"Hello Alice, I received your message securely!")
    print("Bob sent secure message to Alice")
    
    # Alice receives the message
    sender, encrypted_msg = network.get_next_message("alice")
    decrypted = alice_ready.receive_secure_message(encrypted_msg)
    print(f"Alice received and decrypted: {decrypted.decode()}")
    
    return alice_ready, bob_ready


async def main():
    """Main function demonstrating the use of the SIGMA protocol."""
    print("=== SIGMA Protocol Demo ===")
    
    # Setup users
    alice, bob, network = await setup_users()
    
    # Run the handshake
    alice_ready, bob_ready = await run_handshake(alice, bob, network)
    
    print("\n=== Session Information ===")
    print(f"Alice's peer: {alice_ready.peer}")
    print(f"Bob's peer: {bob_ready.peer}")
    print(f"Session key match: {alice_ready.session_key == bob_ready.session_key}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
    asyncio.run(main())