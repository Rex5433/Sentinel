"""Parse a manually selected local export to stdout; no files are written."""

import argparse
import json
from pathlib import Path
import sys

from .common import MAX_INPUT_BYTES, ParseInputError
from .linux import parse_linux
from .windows import parse_windows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=("windows-json", "windows-csv", "linux-text", "linux-journal-json"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--upload-id", required=True, help="local provenance reference, not a credential")
    args = parser.parse_args()
    try:
        with args.path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if args.format.startswith("windows-"):
            result = parse_windows(data, file_format=args.format.removeprefix("windows-"),
                                   source_file=args.path.name, upload_id=args.upload_id)
        else:
            result = parse_linux(data, file_format=args.format.removeprefix("linux-"),
                                 source_file=args.path.name, upload_id=args.upload_id)
        print(json.dumps(result.to_dict(), ensure_ascii=True, allow_nan=False, indent=2))
        return 1 if result.rejected else 0
    except (OSError, ParseInputError) as exc:
        # Do not dump source evidence or filesystem paths in fatal error messages.
        reason = str(exc) if isinstance(exc, ParseInputError) else "unable to read selected local file"
        print(f"Parse failed: {reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
