"""
Types used across the package.
"""

from typing import (
    NamedTuple,
    Literal,
    Union,
    Optional,
    Tuple,
    Callable,
    Generator,
    Any,
)

from typing import TypeAlias

# fmt: off
FileParsingMode: TypeAlias = Union[
    Literal["line"], Literal["chunked"], Literal["raw"]
]

PlaintextEncoding: TypeAlias = Union[
    Literal["base64"], Literal["base64url"], Literal["base32"],
    Literal["base32hex"], Literal["base16"], Literal["plain"]
]

DecipherProcessingGroup: TypeAlias = Callable[
    [], Generator[Callable[[], bytes], None, None]
]
# fmt: on


class Options(NamedTuple):
    """Options specifying how to decrypt files"""

    mode: FileParsingMode
    plaintext_encoding: Optional[PlaintextEncoding]
    encoding: str = "utf-8"
    recursive: bool = False
    algorithm_options: Optional[Any] = None


__all__: Tuple[str, ...] = (
    "DecipherProcessingGroup",
    "Options",
    "PlaintextEncoding",
    "FileParsingMode",
)
