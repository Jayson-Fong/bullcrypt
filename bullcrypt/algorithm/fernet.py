import argparse
import functools
from typing import Optional, Dict, Tuple

from cryptography.fernet import Fernet as _Fernet

from .. import types
from ..algorithm import Algorithm


class Fernet(Algorithm):
    @classmethod
    def _decrypt_one(cls, payload: bytes, key: str, options: types.Options):
        return _Fernet(key.encode(options.encoding)).decrypt(payload)

    @classmethod
    def _decryption_group(cls, payload: bytes, options: types.Options):
        for key in options.algorithm_options["key"]:
            yield functools.partial(cls._decrypt_one, payload=payload, key=key, options=options)

    @classmethod
    def register_args(cls, algorithm_name: str, parser):
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
        key: Optional[str] = getattr(args, f"{algorithm_name}.key")
        if not key:
            raise ValueError(
                "A Fernet key is required and must be 32 url-safe base64-encoded bytes."
            )

        return {
            "key": key,
        }


__all__: Tuple[str, ...] = ("Fernet",)
