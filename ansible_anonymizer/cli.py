#!/usr/bin/env python3
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
import argparse
import pathlib

import yaml

from ansible_anonymizer.anonymizer import anonymize_struct, anonymize_text_block


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file_path", type=pathlib.Path)
    parser.add_argument("--format", choices=["text", "yaml"], type=str, default="text")
    args = parser.parse_args()

    if args.format == "text":
        print(anonymize_text_block(args.file_path.read_text()), end="")
    elif args.format == "yaml":
        print(anonymize_struct(yaml.safe_load(args.file_path.read_text())))


if __name__ == "__main__":
    main()
