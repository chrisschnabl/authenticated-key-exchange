import base64
from typing import Any
from nacl.public import PrivateKey, PublicKey
from nacl.signing import VerifyKey, SigningKey

class Base64SerializerMixin:
    """
    Mixin to automatically decode a base64 encoded value into raw bytes on
    instantiation and to encode its value back to base64 on demand.

    The class using this mixin must implement an `encode()` method (returning raw bytes)
    and be constructible with raw bytes.
    """
    @staticmethod
    def base64_encode(data: bytes) -> str:
        return base64.b64encode(data).decode('ascii')

    @staticmethod
    def base64_decode(data: str | bytes) -> bytes:
        if isinstance(data, str):
            data = data.strip().encode('ascii')  # strip whitespace
        return base64.b64decode(data)

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, value: str | bytes | object) -> Any:
        # If already an instance of this class, return it.
        if isinstance(value, cls):
            return value

        # If value is an instance of an underlying type, wrap it by
        # calling its encode() method (which returns raw bytes).
        for base in cls.__bases__:
            if base not in (Base64SerializerMixin, object) and isinstance(value, base):
                return cls(value.encode())

        try:
            raw = cls.base64_decode(value)
        except Exception as e:
            raise ValueError("Invalid base64 encoding") from e
        return cls(raw)

    def to_base64(self) -> str:
        """Return a base64‑encoded string representation of this instance."""
        return self.__class__.base64_encode(self.encode())


# ------------------------------------------------------------------------------
# Specialized Types for Keys and Generic Byte Fields
# ------------------------------------------------------------------------------

class PydanticPrivateKey(PrivateKey, Base64SerializerMixin):
    """A PrivateKey with automatic base64 serialization for Pydantic."""
    pass


class PydanticPublicKey(PublicKey, Base64SerializerMixin):
    """A PublicKey with automatic base64 serialization for Pydantic."""
    pass


class PydanticVerifyKey(VerifyKey, Base64SerializerMixin):
    """A VerifyKey with automatic base64 serialization for Pydantic."""
    pass


class PydanticSigningKey(SigningKey, Base64SerializerMixin):
    """A SigningKey with automatic base64 serialization for Pydantic."""
    pass


class Base64Bytes(bytes, Base64SerializerMixin):
    """
    A bytes subclass that automatically serializes/deserializes to/from base64.
    Useful for non-key byte fields (nonces, MACs, signatures, etc.).
    """
    def encode(self) -> bytes:
        return self  # raw bytes are already in the proper form