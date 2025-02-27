from nacl.signing import SigningKey

from certificates.certificate_authority import CertificateAuthority
from network.simulated_network import SimulatedNetwork
from sigma.user import User


def main():
    ca = CertificateAuthority()
    # Generate long-term keys and certificates.
    alice_key = SigningKey.generate()
    ca.issue_certificate("Alice", alice_key.verify_key.encode())
    bob_key = SigningKey.generate()
    ca.issue_certificate("Bob", bob_key.verify_key.encode())

    network = SimulatedNetwork()

    # Create protocol instances.
    alice_proto = User(
        identity="Alice",
        ca=ca,
        network=network,
    )
    bob_proto = User(
        identity="Bob",
        ca=ca,
        network=network,
    )

    network.register_user(alice_proto.identity, alice_proto.receive_message)
    network.register_user(bob_proto.identity, bob_proto.receive_message)

    alice_proto.start_session("Bob")


if __name__ == "__main__":
    main()
