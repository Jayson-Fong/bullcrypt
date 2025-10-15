import pathlib

import pytest

import bullcrypt.utils


def test_unknown_mode(tmp_path: pathlib.Path):
    with pytest.raises(ValueError) as e:
        # noinspection PyTypeChecker
        for _content in bullcrypt.utils.extract_content(
            tmp_path,
            "unknown-mode",
            "plain",
            "utf-8"
        ):
            pass

    assert e.value.args[0] == "Unknown mode unknown-mode"


def test_line_file_decoding_error(tmp_path: pathlib.Path):
    file_path: pathlib.Path = tmp_path / "test"
    with open(file_path, "wb") as file:
        file.write(b"\x95\x28")

    for _ in bullcrypt.utils.extract_content(
        file_path,
        "line",
        "plain",
        "utf-8"
    ):
        pass


def test_line_base64_decoding_error(tmp_path: pathlib.Path):
    file_path: pathlib.Path = tmp_path / "test"
    with open(file_path, "wb") as file:
        file.write(b"G")

    for _ in bullcrypt.utils.extract_content(
        file_path,
        "line",
        "base64",
        "utf-8"
    ):
        pass


def test_chunked_base64_decoding_error(tmp_path: pathlib.Path):
    file_path: pathlib.Path = tmp_path / "test"
    with open(file_path, "wb") as file:
        file.write(b"G")

    for _ in bullcrypt.utils.extract_content(
        file_path,
        "chunked",
        "base64",
        "utf-8"
    ):
        pass
