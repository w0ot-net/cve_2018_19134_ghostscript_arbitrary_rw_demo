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

# Any extra arguments are forwarded verbatim to Ghostscript, so the exploit can
# be driven under an arbitrary output device, e.g.:
#
#     ./run.sh -sDEVICE=pdfwrite
#     ./run.sh -sDEVICE=png16m -r300
#
# The exploit's rw_init seam is independent of the page device, so it succeeds
# under any device Ghostscript can actually open. Display-requiring devices
# (x11, display) and devices needing an external server (ijs, opvp) are out of
# scope; they cannot open in this headless container.
USER_ARGS=("$@")

GS_FLAGS=(-dNOSAFER -dBATCH -dNOPAUSE -dQUIET)

have_device=false
have_output=false
prev=""
for a in ${USER_ARGS[@]+"${USER_ARGS[@]}"}; do
    case "$a" in
        -sDEVICE=*) have_device=true ;;
        -o) have_output=true ;;
        -o*) have_output=true ;;
        -sOutputFile=*) have_output=true ;;
        --output=*) have_output=true ;;
    esac
    prev="$a"
done

if $have_device; then
    # An output device was selected. Many output devices (pdfwrite, ps2write,
    # txtwrite, ...) refuse to open without an output file, which would abort
    # Ghostscript before the exploit ever runs. Supply a throwaway sink unless
    # the caller already chose one. The exploit never emits a page, so the file
    # stays empty.
    if ! $have_output; then
        GS_FLAGS+=(-sOutputFile=/dev/null)
        echo "[run.sh] device selected without output file; adding -sOutputFile=/dev/null" >&2
    fi
else
    # No device requested: keep the historical headless default.
    GS_FLAGS+=(-dNODISPLAY)
fi

cd "$SCRIPT_DIR"
exec "$GS_RUN" "$GS_VERSION" -- \
    "${GS_FLAGS[@]}" \
    ${USER_ARGS[@]+"${USER_ARGS[@]}"} \
    /work/exploit_monolithic.ps
