import pathlib
from typing import Callable, Generator
from unittest import mock

import bullcrypt.__main__
import bullcrypt.main
from bullcrypt import types, algorithm


def test_main() -> None:
    """
    Attempts to run __main__.py a random number of times.

    :return: None.
    """

    with mock.patch.object(bullcrypt.main, "main") as patch_main:
        with mock.patch.object(bullcrypt.__main__, "__name__", "__main__"):
            bullcrypt.__main__.init()

    assert patch_main.call_count == 1


def test_erroring_processor(tmp_path: pathlib.Path) -> None:
    # noinspection PyUnusedLocal
    def erroring_processor(*args, **kwargs):
        del args, kwargs
        raise ValueError("Error")

    with mock.patch.object(bullcrypt.main, "_process_file", erroring_processor):
        bullcrypt.main.main(
            [
                "--line",
                "--plain",
                "--fernet.key=8KAadjX51CrZ5NCX0JVKculskzYmkHYE3C_f8N4clpo=",
                "--recursive",
                "fernet",
                str(tmp_path),
            ]
        )


def test_decryption_directory_error(tmp_path: pathlib.Path) -> None:
    class FaultyAlgorithm(algorithm.Algorithm):
        @classmethod
        def decrypt(
            cls, payload: bytes, options: "types.Options"
        ) -> Callable[[], Generator[Callable[[], bytes], None, None]]:
            raise ValueError("Faulty algorithm")

        @classmethod
        def _decryption_group(
            cls, payload: bytes, options: "types.Options"
        ) -> Generator[Callable[[], bytes], None, None]:
            yield from ()

    test_path: pathlib.Path = tmp_path / "test"
    test_path.touch()
    for _ in bullcrypt.main._process_file(
        FaultyAlgorithm,
        str(tmp_path),
        types.Options(mode="raw", plaintext_encoding=None, recursive=True),
    ):
        pass
