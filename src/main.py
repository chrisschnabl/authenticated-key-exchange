from nacl.signing import SigningKey
from pydantic import BaseModel

from msgs import SigmaMessage1, SigmaMessage3
from network.simulated_network import SimulatedNetwork
from sigma.user import Uncertified, User


def main():
    ca_signing_key = SigningKey.generate()
    from certificates.ca import CertificateAuthority  # Import from ca.py

    ca = CertificateAuthority(ca_signing_key)

    network = SimulatedNetwork()

    user_A_signing_key = SigningKey.generate()
    user_B_signing_key = SigningKey.generate()

    user_A = User[Uncertified](
        identity="Alice",
        ca=ca,
        signing_key=user_A_signing_key,
        verify_key=user_A_signing_key.verify_key,
        network=network,
    )
    user_B = User[Uncertified](
        identity="Bob",
        ca=ca,
        signing_key=user_B_signing_key,
        verify_key=user_B_signing_key.verify_key,
        network=network,
    )

    cert_A = user_A.obtain_certificate()  # Now User[Certified]
    cert_B = user_B.obtain_certificate()  # Now User[Certified]

    global sigma_initiator, sigma_responder
    sigma_initiator = cert_A.initiate_sigma("Bob")
    sigma_responder = cert_B.wait_for_sigma("Alice")

    def alice_on_receive(msg: BaseModel, sender: str) -> None:
        global sigma_initiator
        print(f"Alice received: {type(msg)}")
        sigma_initiator.receive_message(msg, sender)

    def bob_on_receive(msg: BaseModel, sender: str) -> None:
        global sigma_responder
        print(f"Bob received: {type(msg)}")
        if isinstance(msg, SigmaMessage1):
            sigma_responder = sigma_responder.process_message1(msg)
            sigma_responder = sigma_responder.send_message2()
        elif isinstance(msg, SigmaMessage3):
            sigma_responder.process_message3(msg)

    network.register_user("Alice", alice_on_receive)
    network.register_user("Bob", bob_on_receive)

    sigma_initiator.send_message1()


if __name__ == "__main__":
    main()
