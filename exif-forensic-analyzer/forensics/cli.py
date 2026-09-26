"""CLI: analyze one or more images for metadata forensics + scam signals.

Usage:
    python -m forensics.cli photo.jpg
    python -m forensics.cli photo.jpg screenshot.png --json
"""

import argparse

from .report import build_report, format_report, report_to_json


def main():
    parser = argparse.ArgumentParser(
        description="EXIF/metadata forensic analyzer with OCR + QR scam detection."
    )
    parser.add_argument("images", nargs="+", help="Image file path(s) to analyze")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a formatted report")
    args = parser.parse_args()

    for path in args.images:
        report = build_report(path)
        if args.json:
            print(report_to_json(report))
        else:
            print(format_report(report))
            print("=" * 70)


if __name__ == "__main__":
    main()
