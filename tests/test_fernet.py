import io
import pathlib
from unittest import mock

import bullcrypt.main


def test_fernet_raw(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with open(test_file, "wb") as file:
        # noinspection SpellCheckingInspection
        file.write(
            b"gAAAAABo7pXag6KIWBdtlWUhl_qnc17dk4b"
            b"J4-mI_f4oxpBCLQc7sMacXD5XIP7v2sJctA"
            b"QJDDJvo7hmCby0zBOG3rIfV2D2ZvirH-kSm"
            b"X9rrvkk5dB7sUhvJUP6B7qG_xAaWzx823_5"
        )

    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        # noinspection SpellCheckingInspection
        bullcrypt.main.main(
            [
                "--raw",
                "--fernet.key=eBUADWmyqd8diJhRb2Kps6ZMbDqzLOXj2_6ILmFs-sE=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    # noinspection SpellCheckingInspection
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in result
