#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$SCRIPT_DIR/gs.conf" ]; then
    echo "No gs.conf found. Creating from gs.conf.example..."
    cp "$SCRIPT_DIR/gs.conf.example" "$SCRIPT_DIR/gs.conf"
fi

# shellcheck disable=SC1091
source "$SCRIPT_DIR/gs.conf"

if [ ! -x "$GS_RUN" ]; then
    echo "gs-run not found at $GS_RUN"
    echo "Edit gs.conf to point GS_RUN at your ghostscript_version_graveyard/gs-run"
    exit 1
fi

cd "$SCRIPT_DIR"
exec "$GS_RUN" "$GS_VERSION" -- \
    -dNOSAFER -dBATCH -dNOPAUSE -dNODISPLAY -dQUIET \
    /work/exploit_monolithic.ps
