#!/usr/bin/env bash
set -euo pipefail

relay_url=${REVERSH_RELAY_URL:-"wss://dev.tsuku.re/reverssh-client/"}
source_zip=${REVERSH_SOURCE_ZIP:-"https://github.com/arm64be/reverSSH/archive/refs/heads/main.zip"}
base_dir=${REVERSH_CLIENT_DIR:-"${HOME:-$PWD}/.reverssh/client"}
state_dir=${REVERSH_STATE_DIR:-"${HOME:-$PWD}/.reverssh"}
shell_path=${REVERSH_SHELL:-"${SHELL:-}"}

if command -v python3 >/dev/null 2>&1; then
    python_bin=python3
elif command -v python >/dev/null 2>&1; then
    python_bin=python
else
    echo "reverSSH setup failed: python3 or python is required" >&2
    exit 1
fi

if ! "$python_bin" - <<'PY' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
then
    echo "reverSSH setup failed: Python 3.11+ is required" >&2
    exit 1
fi

if [ -z "$shell_path" ]; then
    if [ -x /bin/bash ]; then
        shell_path=/bin/bash
    elif [ -x /bin/sh ]; then
        shell_path=/bin/sh
    else
        shell_path=sh
    fi
fi

detect_identifier() {
    if [ -n "${REVERSH_IDENTIFIER:-}" ]; then
        printf '%s\n' "$REVERSH_IDENTIFIER"
        return
    fi
    user_part=$(id -un 2>/dev/null || whoami 2>/dev/null || printf 'user')
    host_part=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'host')
    raw="${user_part}-${host_part}"
    "$python_bin" - "$raw" <<'PY'
import re
import sys
value = re.sub(r"[^A-Za-z0-9_.-]+", "-", sys.argv[1]).strip(".-")
print(value or "reverssh-client")
PY
}

identifier=$(detect_identifier)
src_dir="$base_dir/src"
download_path="$base_dir/reverssh.zip"

mkdir -p "$base_dir" "$state_dir"

echo "reverSSH setup: relay $relay_url" >&2
echo "reverSSH setup: identifier $identifier" >&2
if [ -n "${REVERSH_OPERATOR_KEYS:-}" ]; then
    echo "reverSSH setup: strict non-interactive operator key allowlist enabled" >&2
fi
echo "reverSSH setup: installing source under $src_dir" >&2

"$python_bin" - "$source_zip" "$download_path" "$src_dir" <<'PY'
from __future__ import annotations

import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

source_url = sys.argv[1]
download_path = Path(sys.argv[2])
src_dir = Path(sys.argv[3])

tmp_dir = Path(tempfile.mkdtemp(prefix="reverssh-bootstrap-"))
try:
    request = urllib.request.Request(source_url, headers={"User-Agent": "reverSSH-bootstrap"})
    with urllib.request.urlopen(request, timeout=60) as response:
        download_path.write_bytes(response.read())
    extract_dir = tmp_dir / "extract"
    with zipfile.ZipFile(download_path) as archive:
        archive.extractall(extract_dir)
    roots = [path for path in extract_dir.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise SystemExit("reverSSH setup failed: unexpected source archive layout")
    if src_dir.exists():
        shutil.rmtree(src_dir)
    shutil.move(str(roots[0]), str(src_dir))
finally:
    shutil.rmtree(tmp_dir, ignore_errors=True)
PY

echo "reverSSH client starting; use Ctrl-C to stop" >&2
export PYTHONPATH="$src_dir${PYTHONPATH:+:$PYTHONPATH}"
exec "$python_bin" -m reverssh.client \
    --relay "$relay_url" \
    --identifier "$identifier" \
    --state-dir "$state_dir" \
    --shell "$shell_path"
