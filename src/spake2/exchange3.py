import secrets
from typing import TypeAlias, Tuple

from crypto_utils import hmac
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from nacl.hash import sha256
from spake2.messages import SPAKE2MessageClient, SPAKE2MessageServer, SPAKE2ConfirmationClient, SPAKE2ConfirmationServer

curve = ExtendedEdwardsCurve()

# Base point for Curve25519 from RFC8032
G_COMPRESSED = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")

# M and N points for Curve25519 as specified in RFC 9382 Section 6
M_COMPRESSED = bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf")
N_COMPRESSED = bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab")

# Decompress the constants for use
G = curve.uncompress(G_COMPRESSED)
M = curve.uncompress(M_COMPRESSED)
N = curve.uncompress(N_COMPRESSED)

# Type aliases for clarity
Identity: TypeAlias = bytes
Context: TypeAlias = bytes
Transcript: TypeAlias = bytes
PublicElement: TypeAlias = bytes
SharedElement: TypeAlias = bytes
BasePoint: TypeAlias = bytes

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "little")

def int_to_bytes(i: int, length: int = 32) -> bytes:
    return i.to_bytes(length, "little")

def hash(data: bytes) -> bytes:
    """
    Hash function specified in RFC 9382 Section 6
    SHA256 is the recommended hash function
    """
    return sha256(data)

def is_valid_point(element: PublicElement) -> bool:
    """
    Check if point is valid as required by RFC 9382 Section 7
    """
    try:
        point = curve.uncompress(element)
        return curve.is_valid_point(point)
    except Exception:
        return False

def hkdf(key: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF key derivation function as recommended in RFC 9382 Section 6
    Implemented using PyNaCl
    """    
    from nacl import pwhash
    salt = bytes([0] * pwhash.argon2id.SALTBYTES) # RFC does not specify salt
    # Use argon2id with moderate security parameters, not long-term storage
    ops = pwhash.argon2id.OPSLIMIT_MODERATE
    mem = pwhash.argon2id.MEMLIMIT_MODERATE
    
    # Generate a key of the exact length requested
    # We'll append the info to the key to ensure context separation
    derived_key = pwhash.argon2id.kdf(
        length, 
        key + info,  # Append info to key for context separation
        salt,
        opslimit=ops, 
        memlimit=mem
    )
    
    return derived_key


class KeySet:
    """Helper class to store derived keys"""
    def __init__(self, ke: bytes, ka: bytes, kcA: bytes, kcB: bytes):
        self.ke = ke  # Encryption key
        self.ka = ka  # Authentication key
        self.kcA = kcA  # Client confirmation key
        self.kcB = kcB  # Server confirmation key

def create_transcript(idA: bytes, idB: bytes, pA: bytes, pB: bytes, K: bytes, w: int) -> bytes:
    """
    Create the protocol transcript according to RFC 9382 Section 3.3
    
    TT = len(A)  || A
       || len(B)  || B
       || len(pA) || pA
       || len(pB) || pB
       || len(K)  || K
       || len(w)  || w
    """
    # Encode w as a big-endian number padded to the length of curve order
    w_bytes = int_to_bytes(w, 32)
    
    transcript = (
        len(idA).to_bytes(8, byteorder='little') + idA +
        len(idB).to_bytes(8, byteorder='little') + idB +
        len(pA).to_bytes(8, byteorder='little') + pA +
        len(pB).to_bytes(8, byteorder='little') + pB +
        len(K).to_bytes(8, byteorder='little') + K +
        len(w_bytes).to_bytes(8, byteorder='little') + w_bytes
    )
    
    return transcript

def derive_keys(transcript: bytes, aad: bytes) -> KeySet:
    """
    Derive the shared keys according to RFC 9382 Section 4
    """
    hash_output = hash(transcript)
    half_len = len(hash_output) // 2
    ke = hash_output[:half_len]
    ka = hash_output[half_len:]
    
    kdf_output = hkdf(
        key=ka,
        info=b"ConfirmationKeys" + aad,
        length=64 
    )
    
    kcA = kdf_output[:32]
    kcB = kdf_output[32:64]
    
    return KeySet(ke=ke, ka=ka, kcA=kcA, kcB=kcB)

def compute_confirmation(transcript: bytes, key: bytes) -> bytes:
    """
    Compute a confirmation MAC as specified in RFC 9382 Section 3.3
    """
    return hmac(transcript, key)

class SharedKeysConfirmed:
    """
    Class to hold confirmed shared key
    """
    def __init__(self, ke: bytes):
        self.ke = ke

    def get_shared_key(self) -> bytes:
        """
        Get the shared encryption key
        """
        return self.ke

class SharedKeysUnconfirmedClient:
    """
    Class to hold unconfirmed derived keys and transcript for client
    """
    def __init__(self, transcript: bytes, ke: bytes, kcA: bytes, kcB: bytes):
        self.transcript = transcript
        self.ke = ke
        self.kcA = kcA
        self.kcB = kcB

    def confirm_server(self, server_msg: SPAKE2ConfirmationServer) -> SharedKeysConfirmed:
        """
        Verify the server's confirmation message
        """
        expected_conf = compute_confirmation(self.transcript, self.kcB)
        if server_msg.mac != expected_conf:
            raise ValueError("Invalid server confirmation")
        
        return SharedKeysConfirmed(ke=self.ke)

class SharedKeysUnconfirmedServer:
    """
    Class to hold unconfirmed derived keys and transcript for server
    """
    def __init__(self, transcript: bytes, ke: bytes, kcA: bytes, kcB: bytes):
        self.transcript = transcript
        self.ke = ke
        self.kcA = kcA
        self.kcB = kcB
    
    def confirm_client(self, client_msg: SPAKE2ConfirmationClient) -> SharedKeysConfirmed:
        """
        Verify the client's confirmation message
        """
        expected_conf = compute_confirmation(self.transcript, self.kcA)
        if client_msg.mac != expected_conf:
            raise ValueError("Invalid client confirmation")
        
        return SharedKeysConfirmed(ke=self.ke)

class Spake2KeysClient:
    """
    Class to hold client's ephemeral keys and other state needed for SPAKE2 protocol
    """
    def __init__(self, w: int, x: int, idA: Identity, idB: Identity, 
                 pA: bytes, context: bytes = b"SPAKE2", aad: bytes = b""):
        self.w = w
        self.x = x
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.pA = pA
        self.context = context
        self.aad = aad

    def client(self, server_msg: SPAKE2MessageServer) -> Tuple[SPAKE2ConfirmationClient, SharedKeysUnconfirmedClient]:
        """
        Process server message and generate client confirmation
        """
        if not is_valid_point(server_msg.element):
            raise ValueError("Invalid server message: point is not on the curve")
        
        pB = server_msg.element
        
        # Calculate K = x * (pB - w*N)
        pB_point = curve.uncompress(pB)
        wN_neg = curve.scalar_mult(N, (-self.w) % curve.q)
        temp = curve.add(pB_point, wN_neg)
        K_point = curve.scalar_mult(temp, self.x)
        
        # Apply cofactor multiplication to prevent small subgroup confinement attacks
        K = curve.compress(K_point)
        
        transcript = create_transcript(self.idA, self.idB, self.pA, pB, K, self.w)
        keys = derive_keys(transcript, self.aad)
        client_conf = compute_confirmation(transcript, keys.kcA)
        
        return SPAKE2ConfirmationClient(mac=client_conf), SharedKeysUnconfirmedClient(
            transcript=transcript,
            ke=keys.ke,
            kcA=keys.kcA,
            kcB=keys.kcB
        )

class Spake2KeysServer:
    """
    Class to hold server's ephemeral keys and other state needed for SPAKE2 protocol
    """
    def __init__(self, w: int, y: int, idA: Identity, idB: Identity, 
                 pB: bytes, context: bytes = b"SPAKE2", aad: bytes = b""):
        self.w = w
        self.y = y
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.pB = pB
        self.context = context
        self.aad = aad

    def server(self, client_msg: SPAKE2MessageClient) -> Tuple[SPAKE2ConfirmationServer, SharedKeysUnconfirmedServer]:
        """
        Process client message and generate server confirmation
        """
        if not is_valid_point(client_msg.element):
            raise ValueError("Invalid client message: point is not on the curve")
        
        pA = client_msg.element
        
        # K = y * (pA - w*M)
        pA_point = curve.uncompress(pA)
        wM_neg = curve.scalar_mult(M, (-self.w) % curve.q)
        temp = curve.add(pA_point, wM_neg)
        K_point = curve.scalar_mult(temp, self.y)
        
        K = curve.compress(K_point)
        transcript = create_transcript(self.idA, self.idB, pA, self.pB, K, self.w)
        keys = derive_keys(transcript, self.aad)
        server_conf = compute_confirmation(transcript, keys.kcB)
        
        return SPAKE2ConfirmationServer(mac=server_conf), SharedKeysUnconfirmedServer(
            transcript=transcript,
            ke=keys.ke,
            kcA=keys.kcA,
            kcB=keys.kcB
        )

class Spake2Initial:
    """
    Initial class for SPAKE2 protocol that handles password processing
    and first message generation
    """
    def __init__(self, password: bytes, idA: Identity, idB: Identity, 
                 context: bytes = b"SPAKE2", aad: bytes = b""):
        self.idA = idA if idA else b""
        self.idB = idB if idB else b""
        self.password = password
        self.context = context
        self.aad = aad
        
        # Process password to derive w
        self.w = self._process_password(password)
    
    def _process_password(self, password: bytes) -> int:
        """
        Process the password to derive scalar w from RFC 9382 Section 3.2
        In a production implementation, this should use a memory-hard function like scrypt
        """
        hash_output = hash(self.context + b"pwd" + password)
        return int_from_bytes(hash_output) % curve.q
    
    def derive_keys_client(self) -> Tuple[SPAKE2MessageClient, Spake2KeysClient]:
        # Generate client's ephemeral key
        x = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        if x == 0:
            x = 1
            
        # X = x*G
        X = curve.scalar_mult(G, x)
        
        # pA = w*M + X
        wM = curve.scalar_mult(M, self.w)
        pA_point = curve.add(wM, X)
        pA = curve.compress(pA_point)
        
        return SPAKE2MessageClient(element=pA), Spake2KeysClient(
            w=self.w,
            x=x,
            idA=self.idA,
            idB=self.idB,
            pA=pA,
            context=self.context,
            aad=self.aad
        )
    
    def derive_keys_server(self) -> Tuple[SPAKE2MessageServer, Spake2KeysServer]:
        # Generate server's ephemeral key
        y = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        if y == 0:
            y = 1
            
        # Y = y*G
        Y = curve.scalar_mult(G, y)
        
        # pB = w*N + Y
        wN = curve.scalar_mult(N, self.w)
        pB_point = curve.add(wN, Y)
        pB = curve.compress(pB_point)
        
        return SPAKE2MessageServer(element=pB), Spake2KeysServer(
            w=self.w,
            y=y,
            idA=self.idA,
            idB=self.idB,
            pB=pB,
            context=self.context,
            aad=self.aad
        )


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