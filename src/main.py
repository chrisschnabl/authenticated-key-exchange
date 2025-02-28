from nacl.signing import SigningKey

# Import the simplified SIGMA implementation
from network.simulated_network import SimulatedNetwork
from user import (
    User, 
    SigmaMessage1,
    SigmaMessage2,
    SigmaMessage3
)

# Import the necessary CA classes
from sigma.ca import CertificateAuthority


# ------------------------------------------------------------------------------
# Demo Functions
# ------------------------------------------------------------------------------

def setup_users():
    """Set up a certificate authority and two users."""
    ca = CertificateAuthority()
    network = SimulatedNetwork()
    
    # Create Alice
    alice_signing_key = SigningKey.generate()
    alice = User(
        identity="alice",
        ca=ca,
        signing_key=alice_signing_key,
        network=network
    )
    
    # Create Bob
    bob_signing_key = SigningKey.generate()
    bob = User(
        identity="bob",
        ca=ca,
        signing_key=bob_signing_key,
        network=network
    )

   # network.register_user("alice", on_receive_ignore)
    #network.register_user("bob", on_receive_ignore)
    
    return alice, bob, network


def run_handshake(alice_user: User, bob_user: User, network: SimulatedNetwork):
    """Run the SIGMA handshake between Alice and Bob."""
    print("\n=== Obtaining Certificates ===")
    
    alice_verified = alice_user.obtain_certificate()
    print("Alice obtained certificate")
    
    bob_verified = bob_user.obtain_certificate()
    print("Bob obtained certificate")
    
    print("\n=== Starting Handshake: Alice initiates, Bob responds ===")
    
    # Alice initiates
    msg1, alice_initiator = alice_verified.initiate_handshake("bob") # TODO CS this should be one class

    print("Alice sent Message 1 to Bob")
    
    # Process message 1
    msg2, bob_waiting = bob_verified.receive_message1(msg1, alice_verified.identity)
    print("Bob received Message 1, sent Message 2 to Alice")
    
    # Process message 2
    msg3, alice_ready = alice_initiator.receive_message2(msg2)
    print("Alice received Message 2, sent Message 3 to Bob")
    
    # Process message 3
    bob_ready = bob_waiting.receive_message3(msg3)
    print("Bob received Message 3, handshake complete")
    
    return alice_ready, bob_ready


def main():
    """Main function demonstrating the use of the SIGMA protocol."""
    print("=== SIGMA Protocol Demo ===")
    
    # Setup users
    alice, bob, network = setup_users()
    
    # Run the handshake
    alice_ready, bob_ready = run_handshake(alice, bob, network)
    
    print("\n=== Session Information ===")
    print(f"Session key match: {alice_ready.session_key == bob_ready.session_key}")
    
    print("\n=== Demo Complete ===")


if __name__ == "__main__":
   main()