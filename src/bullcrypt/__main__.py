"""
Launches the program.

Used for the "python3 -m bullcrypt" syntax.
"""

from typing import Tuple

from . import main


def init() -> None:
    """
    Initialize the main program.

    :return: None.
    """

    if __name__ == "__main__":
        main.main()


init()


__all__: Tuple[str, ...] = ("init",)
