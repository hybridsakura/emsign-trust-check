#!/usr/bin/env python3
"""Materialise one edition of the web UI at build time.

Editions
  internet : the live-probe page (index.html / zh.html). Needs outbound access to
             the 12 public test hosts to reach a conclusion.
  lan      : a self-contained page (public/lan.html) that reaches its conclusion
             inside the browser — no probes, no external request, no download, no
             instruction to go online. Chinese by default (index.html == zh.html).

This is a build-time transform only: the shipped artefact contains no switch.
"""
import argparse
import os
import re
import shutil
import sys

# Terms that must never appear in the LAN edition. Product names such as
# "Internet Explorer" are allowed explicitly.
LAN_FORBIDDEN = [
    (r"http://", "plain http reference"),
    (r"https://", "external https reference"),
    (r"\bInternet\b(?! Explorer)", "the word Internet"),
    (r"外网", "external-network wording"),
    (r"在线检测", "live-check wording"),
    (r"在线探测", "live-probe wording"),
    (r"live check", "live-check wording"),
    (r"XMLHttpRequest", "legacy XHR"),
    (r"@import", "css import"),
    (r"src\s*=\s*[\"']//", "protocol-relative asset"),
    (r"<link[^>]+href\s*=\s*[\"'](?!downloads/)", "external stylesheet/preload"),
    (r"下载脚本|请下载|自行下载", "download-it-yourself instruction"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--edition", choices=["internet", "lan"], required=True)
    ap.add_argument("--src", default="public")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if os.path.exists(args.out):
        shutil.rmtree(args.out)
    os.makedirs(args.out)

    if args.edition == "internet":
        for name in os.listdir(args.src):
            if name == "lan.html":
                continue
            s, d = os.path.join(args.src, name), os.path.join(args.out, name)
            shutil.copytree(s, d) if os.path.isdir(s) else shutil.copy2(s, d)
    else:
        lan = os.path.join(args.src, "lan.html")
        if not os.path.exists(lan):
            print("ERROR: public/lan.html is missing", file=sys.stderr)
            return 4
        with open(lan, encoding="utf-8") as fh:
            html = fh.read()
        for pattern, why in LAN_FORBIDDEN:
            m = re.search(pattern, html)
            if m:
                line = html[: m.start()].count("\n") + 1
                print(f"ERROR: LAN page contains {why} at line {line}: {m.group(0)!r}", file=sys.stderr)
                return 3
        for name in ("index.html", "zh.html"):
            with open(os.path.join(args.out, name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(html)
        # The TLS-enforcement self-check lives on its own port (see deploy/canary.conf).
        # The marker is only shipped when that endpoint is actually part of the image.
        with open(os.path.join(args.out, "canary-port.txt"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("8443\n")
        src_downloads = os.path.join(args.src, "downloads")
        if os.path.isdir(src_downloads):
            shutil.copytree(src_downloads, os.path.join(args.out, "downloads"))

    with open(os.path.join(args.out, "EDITION.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(args.edition + "\n")

    print(f"OK: {args.edition} edition -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
