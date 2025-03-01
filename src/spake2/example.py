from spake2.exchange3 import Spake2Initial

if __name__ == "__main__":
    # Example usage
    password = b"password123"
    context = b"SPAKE2 Example"
    idA = b"client@example.com"
    idB = b"server@example.com"

    alice = Spake2Initial(password=password, context=context, idA=idA, idB=idB)
    bob = Spake2Initial(password=password, context=context, idA=idA, idB=idB)

    alice_msg, alice_keys = alice.derive_keys_client()
    bob_msg, bob_keys = bob.derive_keys_server()

    alice_mu, alice_unconfirmed = alice_keys.client(bob_msg)
    bob_mu, bob_unconfirmed = bob_keys.server(alice_msg)

    alice_confirmed = alice_unconfirmed.confirm_server(bob_mu)
    bob_confirmed = bob_unconfirmed.confirm_client(alice_mu)

    # Get shared keys
    client_key = alice_confirmed.get_shared_key()
    server_key = bob_confirmed.get_shared_key()
    
    # Verify keys match
    print(f"Protocol completed successfully: {True}")
    print(f"Shared keys match: {client_key.hex() == server_key.hex()}")
    print(f"Shared key: {client_key.hex()}")