"""
Wrapper around `cryptography` to decrypt Fernet ciphertexts.
"""

import argparse
import functools
from typing import Optional, Dict, Tuple, TYPE_CHECKING, Callable, Generator, List

from cryptography.fernet import Fernet as _Fernet

from ..algorithm import Algorithm


if TYPE_CHECKING:
    from .. import types


class Fernet(Algorithm):
    """Plugin for decrypting using the Fernet encryption algorithm."""

    @classmethod
    def _decrypt_one(cls, payload: bytes, key: str, options: "types.Options") -> bytes:
        return _Fernet(key.encode(options.encoding)).decrypt(payload)

    @classmethod
    def _decryption_group(
        cls, payload: bytes, options: "types.Options"
    ) -> Generator[Callable[[], bytes], None, None]:
        if not isinstance(options.algorithm_options, dict):
            raise ValueError("Algorithm options expected to be a dict")

        for key in options.algorithm_options["key"]:
            yield functools.partial(
                cls._decrypt_one, payload=payload, key=key, options=options
            )

    @classmethod
    def register_args(
        cls, algorithm_name: str, parser: argparse.ArgumentParser
    ) -> None:
        group = parser.add_argument_group(f"Fernet ({algorithm_name})")
        group.add_argument(
            f"--{algorithm_name}.key",
            dest=f"{algorithm_name}.key",
            action="append",
            default=[],
            help="A 32-byte key encoded as Base64URL",
        )

    @classmethod
    def extract_args(
        cls, algorithm_name: str, args: argparse.Namespace
    ) -> Optional[Dict]:
        key: Optional[List[str]] = getattr(args, f"{algorithm_name}.key", None)
        if not key:
            raise ValueError(
                "A Fernet key is required and must be 32 url-safe base64-encoded bytes."
            )

        key = [k for k in key if k]
        if not key:
            raise ValueError(
                "A Fernet key is required and must be 32 url-safe base64-encoded bytes."
            )

        return {
            "key": key,
        }


__all__: Tuple[str, ...] = ("Fernet",)
