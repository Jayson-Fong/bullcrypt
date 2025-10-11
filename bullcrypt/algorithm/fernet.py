import argparse
from typing import Optional, Dict, Tuple

from bullcrypt import types
from bullcrypt.algorithm import Algorithm
from cryptography.fernet import Fernet as _Fernet


class Fernet(Algorithm):
    @classmethod
    def decrypt(cls, payload: bytes, options: types.Options):
        key = _Fernet(options.algorithm_options["key"].encode(options.encoding))
        return key.decrypt(payload)

    # noinspection PyUnusedLocal
    @classmethod
    def register_args(cls, algorithm_name: str, parser):
        group = parser.add_argument_group("Fernet")
        group.add_argument(
            "--key",
            dest=f"{algorithm_name}.key",
            required=True,
            help="A 32-byte key encoded as Base64URL",
        )

    # noinspection PyUnusedLocal
    @classmethod
    def extract_args(cls, algorithm_name: str, args: argparse.Namespace) -> Optional[Dict]:
        return {
            "key": getattr(args, f"{algorithm_name}.key"),
        }


__all__: Tuple[str, ...] = ("Fernet",)
