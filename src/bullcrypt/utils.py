"""
General utilities
"""

import base64
import logging
import pathlib
from importlib.metadata import entry_points
from typing import (
    Any,
    Sequence,
    Tuple,
    Dict,
    Callable,
    TypeVar,
    Union,
    Optional,
    TYPE_CHECKING,
    Generator,
)

if TYPE_CHECKING:
    from . import types

    try:
        # noinspection PyProtectedMember
        from importlib.metadata import EntryPoints  # type: ignore[no-redef]
    except ImportError:
        # noinspection PyProtectedMember,PyUnresolvedReferences
        from importlib_metadata import EntryPoints  # type: ignore[no-redef]

logger: logging.Logger = logging.getLogger(__name__)


def get_algorithms() -> "EntryPoints":
    """
    Identifies algorithm implementations.

    :return: `EntryPoints` for algorithms.
    """

    return entry_points(group="bullcrypt.algorithm")


T = TypeVar("T", bound=str)
U = TypeVar("U", bound=str)


def get_truthy_attribute(obj: Any, options: Sequence[T], fallback: U) -> Union[T, U]:
    """
    Iterates over an object provided a list of keys and find the first truthy key.

    :param obj: The object to retrieve values from.
    :param options: Attributes to retrieve from `obj`.
    :param fallback: Fallback value if all options fail.
    :return: The first truthy attribute or fallback value.
    """
    for option in options:
        if getattr(obj, option, False):
            return option

    return fallback


DECODERS: Dict[str, Callable[[str], bytes]] = {
    "base64": base64.b64decode,
    "base64url": base64.urlsafe_b64decode,
    "base32": base64.b32decode,
    "base32hex": base64.b32hexdecode,
    "base16": base64.b16decode,
}


def decode_content(
    content: str,
    plaintext_encoding: Optional["types.PlaintextEncoding"],
    encoding: str,
) -> bytes:
    """
    Decodes a plain text content based on a specified encoding.

    :param content: Content to decode into bytes.
    :param plaintext_encoding: Encoding to decode using.
    :param encoding: Encoding to use when converting from a string to bytes plainly.
    :return: Bytes from decoding `content`.
    """

    if plaintext_encoding is None or plaintext_encoding == "plain":
        return content.encode(encoding)

    return DECODERS[plaintext_encoding](content)


def extract_content(
    file_path: pathlib.Path,
    mode: "types.FileParsingMode",
    plaintext_encoding: Optional["types.PlaintextEncoding"],
    encoding: str,
) -> Generator[bytes, None, None]:
    """
    Extracts content from a file path.

    Modes:
    - raw: Reads the file as raw and returns the content.
    - chunked: Joins the file's lines, reconstructing it, and decode as needed.
    - line: Processes each line as a separate ciphertext. Otherwise, identical to "chunked".

    :param file_path: Path to file for parsing.
    :param mode: Mode to extract using (raw, chunked, or line).
    :param plaintext_encoding: Encoding to decode non-plaintext strings using.
    :param encoding: Encoding to use for direct encoding from string to bytes.
    :return: Generator of decoded bytes.
    """

    if mode == "raw":
        with open(file_path, "rb") as file:
            yield file.read()
    elif mode == "chunked":
        # noinspection PyBroadException
        # pylint: disable=broad-exception-caught
        try:
            with open(file_path, "r", encoding=encoding) as file:
                yield decode_content(
                    "".join(file.read().splitlines()),
                    plaintext_encoding,
                    encoding,
                )
        except Exception:
            logger.exception("Failed to decode file: %s", file_path)
    elif mode == "line":
        # noinspection PyBroadException
        # pylint: disable=broad-exception-caught
        try:
            with open(file_path, "r", encoding=encoding) as file:
                for line in file:
                    line = line.strip()

                    if line:
                        # noinspection PyBroadException
                        # pylint: disable=broad-exception-caught
                        try:
                            yield decode_content(line, plaintext_encoding, encoding)
                        except Exception:
                            logger.exception("Failed to decode line: %s", line)
        except Exception:
            logger.exception("Failed to decode file: %s", file_path)
    else:
        raise ValueError(f"Unknown mode {mode}")


__all__: Tuple[str, ...] = ("get_algorithms", "get_truthy_attribute")
