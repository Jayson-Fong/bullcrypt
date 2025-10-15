"""
Abstract algorithm for decryption handling.
"""

import argparse
import functools
import pathlib
from abc import abstractmethod
from typing import Optional, Tuple, TYPE_CHECKING, Generator, Callable, Any

from .. import utils

if TYPE_CHECKING:
    from .. import types


class Algorithm:
    """Algorithm for decryption."""

    @classmethod
    def extract_content(
        cls, file_path: pathlib.Path, options: "types.Options"
    ) -> Generator[bytes, None, None]:
        """
        Extract ciphertext from a file.

        :param file_path: File path to extract ciphertext from.
        :param options: Parsing options.
        :return: Generator of ciphertext bytes.
        """

        yield from utils.extract_content(
            file_path,
            mode=options.mode,
            plaintext_encoding=options.plaintext_encoding,
            encoding=options.encoding,
        )

    @classmethod
    @abstractmethod
    def _decryption_group(
        cls, payload: bytes, options: "types.Options"
    ) -> Generator[Callable[[], bytes], None, None]:
        yield from ()

    @classmethod
    def decrypt(
        cls, payload: bytes, options: "types.Options"
    ) -> Callable[[], Generator[Callable[[], bytes], None, None]]:
        """
        Provides a callable for a decryption group.

        Decryption groups are used to effectively pass exception
        handling to the caller rather than handling it internally.
        Each group consists of a generator of callables, thereby
        allowing the caller to halt decryption when they are
        satisfied with the results and handle exceptions how
        they choose to do so.

        :param payload: Bytes to decrypt.
        :param options: Decryption options.
        :return: Callable that provides a generator of callables,
            which provides decrypted byte output.
        """

        return functools.partial(cls._decryption_group, payload, options)

    # noinspection PyUnusedLocal
    @classmethod
    def register_args(
        cls, algorithm_name: str, parser: argparse.ArgumentParser
    ) -> None:
        """
        Registers arguments to an argument parser.

        :param algorithm_name: Name of the algorithm.
        :param parser: An argument parser.
        :return: None.
        """

        del algorithm_name, parser

    # noinspection PyUnusedLocal
    # pylint: disable=useless-return
    @classmethod
    def extract_args(
        cls, algorithm_name: str, args: argparse.Namespace
    ) -> Optional[Any]:
        """
        Normalizes arguments to a more friendly form.

        :param algorithm_name: Name of the algorithm.
        :param args: Arguments extracted from the command line.
        :return: Any structure desired by the plugin.
        """

        del algorithm_name, args
        return None


__all__: Tuple[str, ...] = ("Algorithm",)
