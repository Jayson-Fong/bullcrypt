from unittest import mock

import bullcrypt.__main__
import bullcrypt.main


def test_main() -> None:
    """
    Attempts to run __main__.py a random number of times.

    :return: None.
    """

    with mock.patch.object(bullcrypt.main, "main") as patch_main:
        with mock.patch.object(bullcrypt.__main__, "__name__", "__main__"):
            bullcrypt.__main__.init()

    assert patch_main.call_count == 1
