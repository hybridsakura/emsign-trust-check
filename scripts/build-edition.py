#!/usr/bin/env python3
"""Materialise one edition of the web UI at build time.

Editions
  internet : live TLS probes against the 12 test hosts + connectivity handling
  lan      : no live probe, no external request, no Internet-related prompt

This is a build-time transform only — the shipped artefact contains no switch.
"""
import argparse
import os
import re
import shutil
import sys

INTERNET_BLOCK = re.compile(r"<!-- internet-only -->.*?<!-- /internet-only -->", re.S)
LAN_BLOCK = re.compile(r"<!-- lan-only -->.*?<!-- /lan-only -->", re.S)
ANY_MARKER = re.compile(r"<!-- /?(internet|lan)-only -->")

# Terms that must never appear in the LAN edition: they would either trigger a
# network request or tell an air-gapped operator to go online.
LAN_FORBIDDEN = ["fetch(", "https://", "外网", "Internet", "在线检测", "在线探测", "live check"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--edition", choices=["internet", "lan"], required=True)
    ap.add_argument("--src", default="public")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    shutil.copytree(args.src, args.out)

    for root, _, files in os.walk(args.out):
        for name in files:
            if not name.endswith(".html"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as fh:
                html = fh.read()

            html = INTERNET_BLOCK.sub("", html) if args.edition == "lan" else LAN_BLOCK.sub("", html)
            # Drop the markers of the block that was kept (the removed block took its own markers with it).
            html = ANY_MARKER.sub("", html)
            if ANY_MARKER.search(html):
                print(f"ERROR: unclosed edition marker in {path}", file=sys.stderr)
                return 2

            if args.edition == "lan":
                hits = [term for term in LAN_FORBIDDEN if term in html]
                if hits:
                    print(f"ERROR: LAN edition still contains {hits} in {path}", file=sys.stderr)
                    return 3

            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(html)

    with open(os.path.join(args.out, "EDITION.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(("lan" if args.edition == "lan" else "internet") + "\n")

    print(f"OK: {args.edition} edition -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
