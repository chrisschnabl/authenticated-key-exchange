from spake2.exchange import Spake2Initial
from spake2.types import Context, Identity

if __name__ == "__main__":
    # Example usage
    password = b"password123"
    context = Context(value=b"SPAKE2 Example")
    idA = Identity(value=b"client1337@cam.ac.uk")
    idB = Identity(value=b"server1337@cam.ac.uk")

    alice = Spake2Initial(password=password, context=context, idA=idA, idB=idB)
    bob = Spake2Initial(password=password, context=context, idA=idA, idB=idB)

    alice_msg, alice_keys = alice.derive_keys_client()
    bob_msg, bob_keys = bob.derive_keys_server()

    alice_mu, alice_unconfirmed = alice_keys.client(bob_msg)
    bob_mu, bob_unconfirmed = bob_keys.server(alice_msg)

    alice_confirmed = alice_unconfirmed.confirm(bob_mu)
    bob_confirmed = bob_unconfirmed.confirm(alice_mu)

    client_key = alice_confirmed.get_shared_key()
    server_key = bob_confirmed.get_shared_key()
    
    print(f"Protocol completed successfully: {True}")
    print(f"Shared keys match: {client_key.value.hex() == server_key.value.hex()}")
    print(f"Shared key: {client_key.value.hex()}")