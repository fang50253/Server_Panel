#!/usr/bin/env python3
"""Add the traffic-filter includes to the public vhosts (idempotent).

Each `server { ... }` block gets `include /etc/nginx/snippets/monitor-tf-<port>.conf;`
right after its `server_name` line, where <port> comes from the block's listen
directive (80 or 443). Blocks that already include it are skipped.

Usage: nginx-tf-include.py /etc/nginx/sites-enabled/example.com.conf ...
"""

import re
import sys

MARKER = "network traffic filter"


def server_blocks(text):
    """Yield (body_start, body_end) offsets for every top-level server block."""
    for match in re.finditer(r"(^|\n)([ \t]*)server\s*\{", text):
        start = text.index("{", match.start())
        depth = 0
        i = start
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    yield start, i
                    break
            i += 1


def block_port(body):
    listens = re.findall(r"^\s*listen\s+([^;]+);", body, re.M)
    if any(re.search(r"\b443\b", item) for item in listens):
        return 443
    if any(re.search(r"\b80\b", item) for item in listens):
        return 80
    return None


def patch(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()

    inserts = []
    for start, end in server_blocks(text):
        body = text[start:end]
        port = block_port(body)
        if port is None:
            continue
        snippet = f"/etc/nginx/snippets/monitor-tf-{port}.conf"
        if snippet in body:
            continue
        name = re.search(r"^([ \t]*)server_name\s+[^;]+;[^\n]*\n", body, re.M)
        if not name:
            continue
        indent = name.group(1)
        inserts.append((start + name.end(), f"{indent}include {snippet};  # {MARKER}\n"))

    if not inserts:
        return False
    for position, line in sorted(inserts, reverse=True):
        text = text[:position] + line + text[position:]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return True


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: nginx-tf-include.py <vhost> [...]")
    changed = [path for path in sys.argv[1:] if patch(path)]
    for path in changed:
        print(f"patched {path}")
    if not changed:
        print("nothing to patch")


if __name__ == "__main__":
    main()
