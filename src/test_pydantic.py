import base64
from pydantic import BaseModel, ConfigDict
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey

# A mixin that provides universal base64 decoding (for input) and string conversion (for output)
class Base64KeyMixin:
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        # If already an instance of the key type, return it.
        if isinstance(v, cls):
            return v
        # If v is a string, assume it is an ascii-encoded base64 string.
        if isinstance(v, str):
            v = v.encode('ascii')
        try:
            raw = base64.b64decode(v)
        except Exception as e:
            raise ValueError("Invalid base64 encoding") from e
        # Construct the key instance from raw bytes.
        return cls(raw)

    def __str__(self) -> str:
        # When converting to string, output a base64-encoded string.
        return base64.b64encode(self.encode()).decode('ascii')

# Define wrapper types that combine the original key classes with the mixin.
class PydanticPrivateKey(PrivateKey, Base64KeyMixin):
    pass

class PydanticPublicKey(PublicKey, Base64KeyMixin):
    pass

class PydanticSigningKey(SigningKey, Base64KeyMixin):
    pass

class PydanticVerifyKey(VerifyKey, Base64KeyMixin):
    pass

# Now you can use these custom types in your models without having to repeat validators.
class KeyModel(BaseModel):
    private_key: PydanticPrivateKey
    public_key: PydanticPublicKey
    signing_key: PydanticSigningKey
    verify_key: PydanticVerifyKey

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        # The json_encoders use the __str__ conversion, which gives a base64 string.
        json_encoders={
            PydanticPrivateKey: lambda v: str(v),
            PydanticPublicKey: lambda v: str(v),
            PydanticSigningKey: lambda v: str(v),
            PydanticVerifyKey: lambda v: str(v),
        }
    )

def main() -> None:
    # Generate keys using our custom wrapper types.
    private_key = PydanticPrivateKey.generate()  # Works because PydanticPrivateKey is a subclass of PrivateKey.
    public_key = private_key.public_key
    signing_key = PydanticSigningKey.generate()
    verify_key = signing_key.verify_key

    keys = KeyModel(
        private_key=private_key,
        public_key=public_key,
        signing_key=signing_key,
        verify_key=verify_key,
    )
    
    # Serialize the model to JSON. The keys are converted to base64 strings.
    json_str = keys.model_dump_json()
    print("Serialized JSON:")
    print(json_str)

    # Re-load the model from JSON. The custom __get_validators__ methods decode the base64 strings.
    loaded_keys = KeyModel.model_validate_json(json_str)
    print("\nLoaded keys:")
    print(loaded_keys)

if __name__ == "__main__":
    main()
