import argparse
import io
import pathlib
from unittest import mock

import pytest

import bullcrypt.main
from bullcrypt import types
from bullcrypt.algorithm import fernet


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


def test_fernet_raw_multikey(tmp_path: pathlib.Path):
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
                "--fernet.key=57ndyQKDwbYrkLKXkT0zPBaIpyfSNktkaWk7HOz_WC8=",
                "--fernet.key=b_aUzNmDOHKF2A7rO7wVZzMF3_CDTui7obSLtthYmUk=",
                "--fernet.key=eBUADWmyqd8diJhRb2Kps6ZMbDqzLOXj2_6ILmFs-sE=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    # noinspection SpellCheckingInspection
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in result


def test_fernet_raw_multikey_invalid(tmp_path: pathlib.Path):
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
                "--fernet.key=JRwWHzueILiaAJjf6xiZBhKG4WCw_e28QUVhdW4J8zk=",
                "--fernet.key=UGOR3EkupTjl4tfpEstGKx1oxBarx8UAbVS_tHemorw=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    assert not result


def test_fernet_chunked(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with open(test_file, "wb") as file:
        # noinspection SpellCheckingInspection
        file.write(
            b"gAAAAABo7pXag6KIWBdtlWUhl_qnc17dk4b\n"
            b"J4-mI_f4oxpBCLQc7sMacXD5XIP7v2sJctA\n"
            b"QJDDJvo7hmCby0zBOG3rIfV2D2ZvirH-kSm\n"
            b"X9rrvkk5dB7sUhvJUP6B7qG_xAaWzx823_5\n"
        )

    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        # noinspection SpellCheckingInspection
        bullcrypt.main.main(
            [
                "--chunked",
                "--plain",
                "--fernet.key=eBUADWmyqd8diJhRb2Kps6ZMbDqzLOXj2_6ILmFs-sE=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    # noinspection SpellCheckingInspection
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in result


def test_fernet_chunked_directory_traversal(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with open(test_file, "wb") as file:
        # noinspection SpellCheckingInspection
        file.write(
            b"gAAAAABo7pXag6KIWBdtlWUhl_qnc17dk4b\n"
            b"J4-mI_f4oxpBCLQc7sMacXD5XIP7v2sJctA\n"
            b"QJDDJvo7hmCby0zBOG3rIfV2D2ZvirH-kSm\n"
            b"X9rrvkk5dB7sUhvJUP6B7qG_xAaWzx823_5\n"
        )

    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        # noinspection SpellCheckingInspection
        bullcrypt.main.main(
            [
                "--chunked",
                "--plain",
                "--fernet.key=eBUADWmyqd8diJhRb2Kps6ZMbDqzLOXj2_6ILmFs-sE=",
                "fernet",
                "--recursive",
                str(tmp_path),
            ]
        )

    result: str = mock_stdout.getvalue()
    # noinspection SpellCheckingInspection
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in result


def test_fernet_chunked_base64(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with open(test_file, "wb") as file:
        # noinspection SpellCheckingInspection
        file.write(
            b"Z0FBQUFBQm83cFhhZzZLSVdCZHRsV1VobF9xbmMxN2RrNGJ\n"
            b"KNC1tSV9mNG94cEJDTFFjN3NNYWNYRDVYSVA3djJzSmN0QV\n"
            b"FKRERKdm83aG1DYnkwekJPRzNySWZWMkQyWnZpckgta1NtW\n"
            b"DlycnZrazVkQjdzVWh2SlVQNkI3cUdfeEFhV3p4ODIzXzU="
        )

    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        # noinspection SpellCheckingInspection
        bullcrypt.main.main(
            [
                "--chunked",
                "--base64",
                "--fernet.key=eBUADWmyqd8diJhRb2Kps6ZMbDqzLOXj2_6ILmFs-sE=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    # noinspection SpellCheckingInspection
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in result


def test_fernet_line(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with open(test_file, "wb") as file:
        # noinspection SpellCheckingInspection
        file.write(
            b"\n\n\n"
            b"gAAAAABo7pkfKtJjd-uivjf9HgdiEE"
            b"PsNNV5sh--5oQ0NVEB86hOokPix6AI"
            b"PLFJIxrW1TQjmzq3b4sXxlOQh3Rhnb"
            b"y1pvKwxer2wUZTIGO2EtYbL0Ppn-Q="
            b"\n\n"
            b"gAAAAABo7pkvZzIsEg3wQOhQu"
            b"DzuYZEWrsD0_t4HuQG2IDlzkO"
            b"juwgaWg5R5rYtpETCYGOiNdYC"
            b"mPFJ2p2xPVuJnc8qas5ZK9A=="
        )

    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        # noinspection SpellCheckingInspection
        bullcrypt.main.main(
            [
                "--line",
                "--plain",
                "--fernet.key=8KAadjX51CrZ5NCX0JVKculskzYmkHYE3C_f8N4clpo=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    # noinspection SpellCheckingInspection
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" in result
    assert "0123456789" in result


def test_fernet_file_not_found(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        # noinspection SpellCheckingInspection
        bullcrypt.main.main(
            [
                "--line",
                "--plain",
                "--fernet.key=8KAadjX51CrZ5NCX0JVKculskzYmkHYE3C_f8N4clpo=",
                "fernet",
                str(test_file),
            ]
        )

    result: str = mock_stdout.getvalue()
    assert result == ""


def test_fernet_invalid_key(tmp_path: pathlib.Path):
    test_file: pathlib.Path = tmp_path / "test"
    with open(test_file, "wb") as file:
        # noinspection SpellCheckingInspection
        file.write(
            b"gAAAAABo7pkfKtJjd-uivjf9HgdiEE"
            b"PsNNV5sh--5oQ0NVEB86hOokPix6AI"
            b"PLFJIxrW1TQjmzq3b4sXxlOQh3Rhnb"
            b"y1pvKwxer2wUZTIGO2EtYbL0Ppn-Q=\n"
            b"gAAAAABo7pkvZzIsEg3wQOhQu"
            b"DzuYZEWrsD0_t4HuQG2IDlzkO"
            b"juwgaWg5R5rYtpETCYGOiNdYC"
            b"mPFJ2p2xPVuJnc8qas5ZK9A=="
        )

    with mock.patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        with pytest.raises(ValueError):
            # noinspection SpellCheckingInspection
            bullcrypt.main.main(
                [
                    "--line",
                    "--plain",
                    "--fernet.key",
                    "",
                    "fernet",
                    str(test_file),
                ]
            )

    result: str = mock_stdout.getvalue()
    assert result == ""


def test_key_not_exist():
    args: argparse.Namespace = argparse.Namespace()

    with pytest.raises(ValueError) as e:
        fernet.Fernet.extract_args("fernet", args)

    assert (
        e.value.args[0]
        == "A Fernet key is required and must be 32 url-safe base64-encoded bytes."
    )


def test_invalid_args():
    with pytest.raises(ValueError) as e:
        for _ in fernet.Fernet.decrypt(
            b"", types.Options(mode="line", plaintext_encoding="plain")
        )():
            pass

    assert e.value.args[0] == "Algorithm options expected to be a dict"
