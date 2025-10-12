import logging
import pathlib
from typing import TYPE_CHECKING, Type, Tuple

from . import cli, types

if TYPE_CHECKING:
    from . import algorithm


logger: logging.Logger = logging.getLogger(__name__)


def _decrypt_file(
    handler: Type["algorithm.Algorithm"],
    file_path: pathlib.Path,
    options: types.Options,
):
    for payload in handler.extract_content(file_path, options):
        yield file_path, handler.decrypt(payload, options)


def _process_file(
    handler: Type["algorithm.Algorithm"], file_path: str, options: types.Options
):
    normalized_path: pathlib.Path = pathlib.Path(file_path)
    if normalized_path.is_file():
        yield from _decrypt_file(handler, normalized_path, options)
    elif options.recursive and normalized_path.is_dir():
        for entry_path in normalized_path.rglob("*"):
            # pylint: disable=broad-exception-caught
            # noinspection PyBroadException
            try:
                yield from _decrypt_file(handler, entry_path, options)
            except Exception:
                logger.exception("Failed to process file: %s", entry_path)


def _default_result_handler(
        result: Tuple[pathlib.Path, types.DecipherProcessingGroup]
):
    file_path, result_generator = result
    for result_entry in result_generator():
        # noinspection PyBroadException
        try:
            print(file_path, "->", result_entry())
            break
        except Exception:
            logger.info(f"Failed deciphering %s", file_path, exc_info=True)


def main():
    handler, files, options = cli.parse()

    for file in files:
        # pylint: disable=broad-exception-caught
        # noinspection PyBroadException
        try:
            for result in _process_file(handler, file, options):
                _default_result_handler(result)
        except Exception:
            logger.exception(f"Failed to process file: %s", file)


__all__: Tuple[str, ...] = ("main",)
