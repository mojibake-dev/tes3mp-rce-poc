# Evidence

* `rce-and-reverse-shell.txt` — gdb `break system` showing `system()` invoked with the attacker's exact
  string, the marker file on disk owned by the server's user, cold-start reliability, and the reverse-shell
  session (lab only; the disclosure PoC uses the marker payload).
* `server-password-matrix.txt` — the four-way test: unpassworded server with no `-P` (executes);
  passworded server with no `-P`, with a wrong `-P`, and with the correct `-P`.
* `passworded-server-rce.txt` — full run against a **passworded** server: rejected cleanly without `-P`,
  full execution with it, and `account files created: 0` (no user account is ever involved).

An earlier version of `server-password-matrix.txt` was invalid because the `sed` that was supposed to set
the server password silently did not match, so all four cases ran against an unpassworded server. The
retained run is the corrected one; the config line is echoed before each case so the setup is verifiable
from the transcript itself.
