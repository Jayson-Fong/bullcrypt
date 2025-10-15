import argparse

from bullcrypt import algorithm, types


def test_decrypt() -> None:
    for _ in algorithm.Algorithm.decrypt(
        b"",
        types.Options(
            mode="raw",
            plaintext_encoding=None,
        ),
    )():
        assert False


def test_register_args() -> None:
    assert (
        algorithm.Algorithm.register_args("algorithm", argparse.ArgumentParser())
        is None
    )


def test_extract_args() -> None:
    assert algorithm.Algorithm.extract_args("algorithm", argparse.Namespace()) is None
