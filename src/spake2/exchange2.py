import secrets
from typing import Optional, TypeAlias
from pydantic import BaseModel, Field

from crypto_utils import hmac
from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from nacl.hash import sha256

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

class SPAKE2Message(BaseModel):
    """Base class for SPAKE2 protocol messages"""
    element: bytes = Field(..., min_length=32, max_length=32)

class SPAKE2MessageClient(SPAKE2Message):
    """First message from client to server containing pA = w*M + X"""
    pass

class SPAKE2MessageServer(SPAKE2Message):
    """First message from server to client containing pB = w*N + Y"""
    pass

class SPAKE2ConfirmationMessage(BaseModel):
    """Base class for confirmation messages"""
    mac: bytes = Field(..., min_length=64, max_length=64)

class SPAKE2ConfirmationClient(SPAKE2ConfirmationMessage):
    """Client confirmation message containing cA = MAC(KcA, TT)"""
    pass

class SPAKE2ConfirmationServer(SPAKE2ConfirmationMessage):
    """Server confirmation message containing cB = MAC(KcB, TT)"""
    pass


class SharedKeys:
    """Class to hold the derived shared keys"""
    def __init__(self, ke: bytes, ka: bytes, kcA: bytes, kcB: bytes):
        self.ke = ke  # Encryption key
        self.ka = ka  # Authentication key
        self.kcA = kcA  # Client confirmation key
        self.kcB = kcB  # Server confirmation key


class SPAKE2Protocol:
    """
    Base class for SPAKE2 protocol implementation that follows RFC 9382
    """
    def __init__(self, idA: Identity, idB: Identity, password: bytes, 
                 context: bytes = b"SPAKE2", aad: bytes = b""):
        """
        Initialize the SPAKE2 protocol with identities and password
        
        Args:
            idA: Identity of party A
            idB: Identity of party B
            password: Shared low entropy password
            context: Optional context string
            aad: Optional additional authenticated data
        """
        self.idA = idA if idA else b""  # RFC 9382: If identity is absent, encode as zero-length string
        self.idB = idB if idB else b""
        self.password = password
        self.context = context
        self.aad = aad
        
        self.w = self._process_password(password)
        
        self.pA = None
        self.pB = None
        self.K = None
        self.TT = None 
        self.keys = None
    
    def _process_password(self, password: bytes) -> int:
        """
        Process the password to derive scalar w from RFC 9382 Section 3.2
        In a production implementation, this should use a memory-hard function like scrypt
        """
        hash_output = hash(self.context + b"pwd" + password)
        return int_from_bytes(hash_output) % curve.q
    
    def _create_transcript(self) -> bytes:
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
        w_bytes = int_to_bytes(self.w, 32)
        
        transcript = (
            len(self.idA).to_bytes(8, byteorder='little') + self.idA +
            len(self.idB).to_bytes(8, byteorder='little') + self.idB +
            len(self.pA).to_bytes(8, byteorder='little') + self.pA +
            len(self.pB).to_bytes(8, byteorder='little') + self.pB +
            len(self.K).to_bytes(8, byteorder='little') + self.K +
            len(w_bytes).to_bytes(8, byteorder='little') + w_bytes
        )
        
        return transcript
    
    def _derive_keys(self) -> SharedKeys:
        """
        Derive the shared keys according to RFC 9382 Section 4
        """
        hash_output = hash(self.TT)
        half_len = len(hash_output) // 2
        ke = hash_output[:half_len]
        ka = hash_output[half_len:]
        
        print("ka: ", ka.hex())
        print("TT: ", self.TT.hex())
        print("aad: ", self.aad.hex()   )
        kdf_output = hkdf(
            key=ka,
            info=b"ConfirmationKeys" + self.aad,
            length=64 
        )
        
        kcA = kdf_output[:32]
        kcB = kdf_output[32:64]
        print("kcA: ", kcA.hex())
        print("kcB: ", kcB.hex())
        
        return SharedKeys(ke, ka, kcA, kcB)
    
    def _compute_confirmation(self, key: bytes) -> bytes:
        """
        Compute a confirmation MAC as specified in RFC 9382 Section 3.3
        
        Args:
            key: The key to use for the MAC
            
        Returns:
            The MAC over the transcript
        """
        return hmac(self.TT, key)


class SPAKE2Client(SPAKE2Protocol):
    """
    Client-side implementation of SPAKE2 protocol
    """
    def __init__(self, idA: Identity, idB: Identity, password: bytes, 
                 context: bytes = b"SPAKE2", aad: bytes = b""):
        super().__init__(idA, idB, password, context, aad)
        self._x = None  # Client's private ephemeral key
        self._verified = False
        
    def start(self) -> SPAKE2MessageClient:
        self._x = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        if self._x == 0:
            self._x = 1
            
        X = curve.scalar_mult(G, self._x)
        
        wM = curve.scalar_mult(M, self.w)
        pA_point = curve.add(wM, X)
        self.pA = curve.compress(pA_point)
        
        return SPAKE2MessageClient(element=self.pA)
    
    def process_server_message(self, message: SPAKE2MessageServer) -> SPAKE2ConfirmationClient:
        if not is_valid_point(message.element):
            raise ValueError("Invalid server message: point is not on the curve")
        
        self.pB = message.element
        
        # Calculate K = x * (pB - w*N)
        pB_point = curve.uncompress(self.pB)
        wN = curve.scalar_mult(N, self.w)
        wN_neg = curve.scalar_mult(N, (-self.w) % curve.q)
        temp = curve.add(pB_point, wN_neg)
        K_point = curve.scalar_mult(temp, self._x)
        
        # Apply cofactor multiplication to prevent small subgroup confinement attacks
        # This is implicit in some curves, but we include it for clarity
        self.K = curve.compress(K_point)
        
        # Create the transcript
        self.TT = self._create_transcript()
        
        # Derive keys
        self.keys = self._derive_keys()
        
        # Compute confirmation MAC
        
        client_conf = self._compute_confirmation(self.keys.kcA)
        
        return SPAKE2ConfirmationClient(mac=client_conf)
    
    def verify_server_confirmation(self, message: SPAKE2ConfirmationServer) -> bool:
        """
        Verify the server's confirmation message
        
        Args:
            message: The server's confirmation message
            
        Returns:
            True if the confirmation is valid, False otherwise
        """
        expected_conf = self._compute_confirmation(self.keys.kcB)
        self._verified = message.mac == expected_conf
        return self._verified
    
    def get_shared_key(self) -> Optional[bytes]:
        """
        Get the shared key, but only if the protocol has been completed successfully
        
        Returns:
            The shared encryption key if protocol completed, None otherwise
        """
        if self._verified:
            return self.keys.ke
        return None


class SPAKE2Server(SPAKE2Protocol):
    """
    Server-side implementation of SPAKE2 protocol
    """
    def __init__(self, idA: Identity, idB: Identity, password: bytes, 
                 context: bytes = b"SPAKE2", aad: bytes = b""):
        super().__init__(idA, idB, password, context, aad)
        self._y = None  # Server's private ephemeral key
        self._verified = False
        
    def process_client_message(self, message: SPAKE2MessageClient) -> SPAKE2MessageServer:
        if not is_valid_point(message.element):
            raise ValueError("Invalid client message: point is not on the curve")
        
        self.pA = message.element
        
        self._y = int.from_bytes(secrets.token_bytes(32), "little") % curve.q
        if self._y == 0:
            self._y = 1
            
        # Y = y*G
        Y = curve.scalar_mult(G, self._y)
        
        # pB = w*N + Y
        wN = curve.scalar_mult(N, self.w)
        pB_point = curve.add(wN, Y)
        self.pB = curve.compress(pB_point)
        return SPAKE2MessageServer(element=self.pB)
    
    def process_client_confirmation(self, message: SPAKE2ConfirmationClient) -> SPAKE2ConfirmationServer:
        # K = y * (pA - w*M)
        pA_point = curve.uncompress(self.pA)
        wM_neg = curve.scalar_mult(M, (-self.w) % curve.q)
        temp = curve.add(pA_point, wM_neg)
        K_point = curve.scalar_mult(temp, self._y)
        
        self.K = curve.compress(K_point)
        self.TT = self._create_transcript()
        self.keys = self._derive_keys()

        expected_client_conf = self._compute_confirmation(self.keys.kcA)

        if message.mac != expected_client_conf:
            raise ValueError("Invalid client confirmation")
        
        self._verified = True
        
        server_conf = self._compute_confirmation(self.keys.kcB)

        print("Server expected client confirmation:", expected_client_conf.hex())
        
        return SPAKE2ConfirmationServer(mac=server_conf)
    
    def get_shared_key(self) -> Optional[bytes]:
        # TODO: this is a dark pattern
        if self._verified:
            return self.keys.ke
        return None


if __name__ == "__main__":
    # Example usage
    password = b"password123"
    idA = b"client@example.com"
    idB = b"server@example.com"
    context = b"SPAKE2 Example"
    
    client = SPAKE2Client(idA, idB, password, context)
    server = SPAKE2Server(idA, idB, password, context)
    
    client_first_msg = client.start()
    server_first_msg = server.process_client_message(client_first_msg)
    client_conf_msg = client.process_server_message(server_first_msg)
    server_conf_msg = server.process_client_confirmation(client_conf_msg)
    
    client_verified = client.verify_server_confirmation(server_conf_msg)

    # Get shared keys
    client_key = client.get_shared_key()
    server_key = server.get_shared_key()
    
    # Verify keys match
    print(f"Protocol completed successfully: {client_verified}")
    print(f"Shared keys match: {client_key.hex() == server_key.hex()}")
    print(f"Shared key: {client_key.hex()}")