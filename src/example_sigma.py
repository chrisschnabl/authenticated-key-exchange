from nacl.signing import SigningKey

from sigma.messages import SigmaMessage1, SigmaMessage2, SigmaMessage3
from network.simulated_network import SimulatedNetwork
from sigma.ca import CertificateAuthority
from sigma.user import User, VerifiedUser


def main() -> None:
    print("=== SIGMA Protocol Demo ===")

    ca = CertificateAuthority()
    network = SimulatedNetwork()

    alice_signing_key = SigningKey.generate()
    bob_signing_key = SigningKey.generate()
    charlie_signing_key = SigningKey.generate()

    alice: VerifiedUser = User(
        identity="alice", ca=ca, signing_key=alice_signing_key
    ).obtain_certificate()
    bob: VerifiedUser = User(
        identity="bob", ca=ca, signing_key=bob_signing_key
    ).obtain_certificate()
    charlie: VerifiedUser = User(
        identity="charlie", ca=ca, signing_key=charlie_signing_key
    ).obtain_certificate()

    network.register_user(alice.identity, alice.receive)
    network.register_user(bob.identity, bob.receive)
    network.register_user(charlie.identity, charlie.receive)

    alice_msg1: SigmaMessage1 = alice.initiate_handshake(bob.identity)
    alice_msg2: SigmaMessage2 = alice.initiate_handshake(charlie.identity)

    print("=== Alice to Bob ===")
    network.send_message(alice.identity, bob.identity, alice_msg1)
    print("=== Alice to Charlie ===")
    network.send_message(alice.identity, charlie.identity, alice_msg2)


    print(
        f"Session key match: {alice.get_session_key(bob.identity) == bob.get_session_key(alice.identity)}"
    )
    print(
        f"Session key match: {alice.get_session_key(charlie.identity) == charlie.get_session_key(alice.identity)}"
    )


    msg = alice.send_secure_message(b"Hello, Bob!", bob.identity)
    bob_msg = bob.receive_secure_message(msg, alice.identity)
    print(f"Bob received message from Alice: {bob_msg}")


    print("=== DEMO END ===")

if __name__ == "__main__":
    main()
