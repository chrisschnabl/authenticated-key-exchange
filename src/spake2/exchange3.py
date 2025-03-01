import secrets
from typing import Tuple

from ed25519.extended_edwards_curve import ExtendedEdwardsCurve
from spake2.messages import SPAKE2MessageClient, SPAKE2MessageServer, SPAKE2ConfirmationClient, SPAKE2ConfirmationServer
from spake2.spake2_utils import is_valid_point, compute_confirmation, create_transcript, derive_keys, int_from_bytes, hash
from spake2.types import Identity

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
        if not is_valid_point(curve, server_msg.element):
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
        if not is_valid_point(curve, client_msg.element):
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