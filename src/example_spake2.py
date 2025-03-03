from spake2.exchange import SharedPassword
from spake2.spake_types import Context, Identity

if __name__ == "__main__":
    # Example usage
    password = b"password123"
    context = Context(value=b"SPAKE2 Example")
    idA = Identity(value=b"client1337@cam.ac.uk")
    idB = Identity(value=b"server1337@cam.ac.uk")

    pka, alice = SharedPassword(password=password, context=context, idA=idA, idB=idB).client()
    pkb, bob = SharedPassword(password=password, context=context, idA=idA, idB=idB).server()

    bob_confirmation, alice_exchange = alice.exchange(pkb)
    alice_confirmation, bob_exchange = bob.exchange(pka)

    alice_confirmed = alice_exchange.confirm(alice_confirmation)
    bob_confirmed = bob_exchange.confirm(bob_confirmation)

    client_key = alice_confirmed.get_shared_key()
    server_key = bob_confirmed.get_shared_key()

    # One could also easily use the Network here

    print(f"Protocol completed successfully: {True}")
    print(f"Shared keys match: {client_key.value.hex() == server_key.value.hex()}")
    print(f"Shared key: {client_key.value.hex()}")
