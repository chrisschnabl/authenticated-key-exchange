from nacl.signing import SigningKey

from messages import SigmaMessage1, SigmaMessage2, SigmaMessage3
from network.simulated_network import SimulatedNetwork
from sigma.ca import CertificateAuthority
from user import User, VerifiedUser


def main() -> None:
    """Main function demonstrating the use of the SIGMA protocol."""
    print("=== SIGMA Protocol Demo ===")


    ca = CertificateAuthority()
    network = SimulatedNetwork()


    alice_signing_key = SigningKey.generate()
    bob_signing_key = SigningKey.generate()
    charlie_signing_key = SigningKey.generate()

    alice: VerifiedUser = User(identity="alice", ca=ca, signing_key=alice_signing_key, network=network).obtain_certificate()
    bob: VerifiedUser = User(identity="bob", ca=ca, signing_key=bob_signing_key, network=network).obtain_certificate()
    charlie: VerifiedUser = User(identity="charlie", ca=ca, signing_key=charlie_signing_key, network=network).obtain_certificate()

    alice_msg1: SigmaMessage1 = alice.initiate_handshake(bob.identity)
    print(f"Alice sent message 1 to Bob, message 1:")
    bob_msg2: SigmaMessage2 = bob.receive(alice_msg1, alice)
    print(f"Bob received message 2 from Alice, message 2:")
    alice_msg3: SigmaMessage3 = alice.receive(bob_msg2, bob)
    print(f"Alice received message 3 from Bob, message 3:")
    _ = bob.receive(alice_msg3, alice)

    print("\n=== Session Information ===")
    print(f"Session key match: {alice.get_session_key(bob.identity) == bob.get_session_key(alice.identity)}")

    alice_msg4: SigmaMessage1 = alice.initiate_handshake(charlie.identity)
    print(f"Alice sent message 1 to Charlie, message 1:")
    charlie_msg2: SigmaMessage2 = charlie.receive(alice_msg4, alice)
    print(f"Charlie received message 2 from Alice, message 2:")
    alice_msg5: SigmaMessage3 = alice.receive(charlie_msg2, charlie)
    print(f"Alice received message 3 from Charlie, message 3:")
    _ = charlie.receive(alice_msg5, alice)

    print("\n=== Session Information ===")
    print(f"Session key match: {alice.get_session_key(charlie.identity) == charlie.get_session_key(alice.identity)}")



if __name__ == "__main__":
    main()
