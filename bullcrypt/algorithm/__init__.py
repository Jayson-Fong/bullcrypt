import argparse
import functools
import pathlib
from abc import abstractmethod
from typing import Optional, Dict, Tuple

from .. import utils, types


class Algorithm:
    @classmethod
    def extract_content(cls, file_path: pathlib.Path, options: types.Options):
        yield from utils.extract_content(
            file_path,
            mode=options.mode,
            plaintext_encoding=options.plaintext_encoding,
            encoding=options.encoding,
        )

    @classmethod
    @abstractmethod
    def _decryption_group(cls, payload: bytes, options: types.Options):
        yield from ()

    @classmethod
    def decrypt(cls, payload: bytes, options: types.Options):
        return functools.partial(cls._decryption_group, payload, options)

    # noinspection PyUnusedLocal
    @classmethod
    def register_args(cls, algorithm_name: str, parser):
        del algorithm_name, parser

    # noinspection PyUnusedLocal
    @classmethod
    def extract_args(
        cls, algorithm_name: str, args: argparse.Namespace
    ) -> Optional[Dict]:
        del algorithm_name, args


__all__: Tuple[str, ...] = ("Algorithm",)
