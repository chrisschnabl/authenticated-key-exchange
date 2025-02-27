from collections.abc import Callable
from typing import Generic, TypeVar

# Type variable for user state.
S = TypeVar("S", bound="UserState")


class UserState:
    """Base class for a user's state."""

    pass


class Init(UserState):
    """State representing an unverified user."""

    def __init__(self, init_secret: str) -> None:
        self.init_secret = init_secret

    def __repr__(self) -> str:
        return f"Init(init_secret={self.init_secret!r})"


class Verified(UserState):
    """State representing a verified user."""

    def __init__(self, verified_data: str) -> None:
        self.verified_data = verified_data

    def __repr__(self) -> str:
        return f"Verified(verified_data={self.verified_data!r})"


class _User(Generic[S]):
    """
    A User parameterized by a state S.
    The constructor is private (by convention). The public API
    only exposes a factory method and state-transition methods.
    """

    def __init__(self, name: str, state: S) -> None:
        self.name: str = name
        self._state: S = state

    @classmethod
    def create(cls: Callable[[str, UserState], S], name: str, init_secret: str = "expected") -> S:
        """
        Factory method for creating a new user in the Init state.
        This method can only be called on a _User with Init state.
        """
        return cls(name, Init(init_secret))

    def verify(self: "_User[Init]", verified_data: str) -> "_User[Verified]":
        """
        Transition from Init to Verified state.
        Only available on a _User in the Init state.
        """
        if self._state.init_secret != "expected":
            raise ValueError("Invalid init secret for verification!")
        return _User(self.name, Verified(verified_data))

    def get_verified_info(self: "_User[Verified]") -> str:
        """
        Get verified information.
        Only available on a _User in the Verified state.
        """
        return self._state.verified_data

    def __repr__(self) -> str:
        return f"User(name={self.name!r}, state={self._state!r})"


# Expose _User as the public API.
User = _User

# Example usage:
if __name__ == "__main__":
    # Create a user in the Init state via the factory method.
    user: User[Init] = User.create("Alice")

    # Transition to Verified state.
    verified_user = user.verify("User has been verified!")
    print(verified_user.get_verified_info())
