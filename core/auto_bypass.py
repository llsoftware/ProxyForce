"""
ProxyForce — automatic direct-routing for proxy-refused destinations.

WHY THIS EXISTS: diagnosed 2026-08-08 against a real corporate proxy that refuses
CONNECT on an arbitrary internal port (1688, unrelated to any documented case like
Outlook's IMAPS/SMTPS) for a destination (`docker.illo.secure`, an internal DNS-
suffixed hostname — the same pattern as `wpad.inet.local`) that has nothing to do
with mail. ProxyForce is a public tool used against many different corporate proxy
policies, each with its own idea of which ports/hosts get refused. Requiring every
user to read a diagnostics WARN, understand what a "Bypass List" is, and manually
paste in a hostname is exactly the kind of network-specific manual tuning the tool
should avoid — the philosophy (per user feedback) is: try the proxy first, and if
it explicitly refuses, ProxyForce should notice and route that destination direct
on its own, on any network, with no user action required.

WHAT THIS DOES NOT DO: auto-bypass ONLY on an explicit refusal — the upstream proxy
answered the CONNECT and said no (a real HTTP status line back, non-2xx). It never
fires on a timeout/unreachable condition (see
SingBoxController._scan_upstream_dial_failures for that, a DIFFERENT failure mode
with a different, correct diagnosis) — a transient network blip is not evidence of
a policy decision, and auto-bypassing on one would silently leak traffic around the
proxy for the wrong reason.

HOW IT IS WIRED (see SingBoxController._check_auto_bypass, called periodically from
_run_steady_state): reject lines are already isolated by
_scan_upstream_rejections() (matches "unexpected status:", the same log line this
module's regex parses further). This module's only job is turning those lines into
structured (host, port, code) tuples — deduping against the current bypass list,
persisting the merge, and triggering a restart are the controller's job (it owns
the config and the restart path), kept out of this module so it can be tested as a
pure function with no engine/GUI involved.
"""

import re

# sing-box logs a refusal as (verified against the bundled 1.13.12 binary, e.g.):
#   "connection: open connection to docker.illo.secure:1688 using
#    outbound/http[proxy-out]: unexpected status: 403 Forbidden"
# The host:port and status code are both right there in the same line that
# _scan_upstream_rejections already isolates — no need to correlate against a
# separate "outbound connection to ..." line.
_REJECTION_RE = re.compile(
    r"open connection to (?P<host>[^\s:]+):(?P<port>\d+) "
    r"using outbound/\S+: unexpected status: (?P<code>\d+)")


def extract_rejections(reject_lines):
    """Parse (host, port, code) out of each already-isolated rejection log line
    (i.e. lines that matched SingBoxController._scan_upstream_rejections). Lines
    that don't match the expected shape are silently skipped — best-effort, since
    a missed extraction just means one host isn't auto-bypassed yet, not a crash.
    """
    out = []
    for ln in reject_lines or []:
        m = _REJECTION_RE.search(ln)
        if m:
            out.append((m.group("host"), int(m.group("port")), int(m.group("code"))))
    return out
