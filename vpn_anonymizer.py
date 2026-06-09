#!/usr/bin/env python3
"""VPN Anonymizer — cycle through Mullvad relays, ping-verify each, and check
whether that exit IP is flagged as VPN / datacenter / proxy (via api.ipapi.is).

Connect/verify/disconnect logic is lifted from clip_fixer's scraper/vpn.py.
Requires: the `mullvad` CLI installed, the daemon running, and an account
logged in.

Public API:
    from vpn_anonymizer import rotate
    rotate(skip=None) -> str | None   # new relay id, or None if none worked

CLI:
    vpn-anonymizer        # walks every WireGuard relay until one is clean
    python3 vpn_anonymizer.py
"""
import argparse
import concurrent.futures
import json
import logging
import os
import random
import re
import subprocess
import sys
import time

logger = logging.getLogger(__name__)

# Quality thresholds for verify_connection(). A relay that pings but with high
# RTT or packet loss is technically reachable but useless for any real workload
# — reject it and try the next one.
_PING_COUNT = 5             # packets to send (need >2 for meaningful stats)
_MAX_AVG_LATENCY_MS = 200   # reject relays whose average RTT exceeds this (wired)
_WIFI_MAX_AVG_LATENCY_MS = 350  # looser ceiling on Wi-Fi: WiFi RTT + jitter
                                # routinely pushes VPN ping past the 200ms wired
                                # bar even on usable relays (see _link_is_wifi).
_MAX_PACKET_LOSS_PCT = 20   # reject relays losing more than this fraction

# Pre-connect ping filter — used by rotate() to sort relays by latency BEFORE
# attempting the expensive connect/verify/detect cycle. A single ICMP ping to
# each relay's public IP from outside the tunnel; ~1-2s for 60+ relays in
# parallel vs. 20-40s per relay for connect/verify.
_PREFILTER_PING_TIMEOUT_S = 2.0          # per-relay ICMP timeout
_PREFILTER_PARALLELISM = 64              # concurrent ICMP probes
_PREFILTER_MAX_LATENCY_MS = 700          # drop relays whose pre-connect RTT
                                          # exceeds this. Deliberately loose: we
                                          # walk viable relays in RANDOM order
                                          # (not nearest-first), so we WANT
                                          # distant relays in the pool — always
                                          # picking the lowest-latency exit would
                                          # loosely triangulate our real location
                                          # and make the rotation pattern
                                          # predictable. The post-connect verify
                                          # ceiling (200ms wired / 350ms Wi-Fi)
                                          # still gates actual in-tunnel speed.


def list_relays(country="us"):
    """Mullvad WireGuard relay IDs from `mullvad relay list` (e.g. us-nyc-wg-001).
    `country` is the 2-letter ISO prefix; pass None to return every country."""
    out = subprocess.run(["mullvad", "relay", "list"], capture_output=True, text=True, timeout=15).stdout
    pattern = r"\b([a-z]{2}-[a-z]+-wg-\d+)\b" if country is None \
              else rf"\b({re.escape(country)}-[a-z]+-wg-\d+)\b"
    return re.findall(pattern, out)


def list_relays_with_ips(country="us"):
    """Same as list_relays() but returns [(relay_id, public_ip), ...]. Pulls the
    IPv4 out of the `(ip[, ipv6...])` token right after each relay id in
    `mullvad relay list` output, e.g. `us-nyc-wg-001 (185.213.155.66)` or
    `us-nyc-wg-001 (185.213.155.66, 2001:db8::1)`. Used by the pre-connect ping
    pre-filter."""
    out = subprocess.run(["mullvad", "relay", "list"], capture_output=True, text=True, timeout=15).stdout
    cc = r"[a-z]{2}" if country is None else re.escape(country)
    # Match the relay id then look for the FIRST IPv4 inside the parenthesized
    # IP block. Lenient about anything else inside the parens (extra IPv6,
    # whitespace, commas, etc.) and anything that comes after.
    pattern = rf"\b({cc}-[a-z]+-wg-\d+)\s*\(\s*(\d+\.\d+\.\d+\.\d+)"
    return re.findall(pattern, out)


def ping_ip(ip, timeout=_PREFILTER_PING_TIMEOUT_S):
    """Send one ICMP packet to `ip` (no VPN tunnel involved — this runs against
    the relay's public IP from the host's regular network path). Returns the
    measured RTT in ms, or None on timeout/error/unreachable.

    NB: ping's wait-for-reply flag has different UNITS per platform:
      - Windows  `-w N` = milliseconds
      - macOS    `-W N` = MILLISECONDS  (BSD ping)
      - Linux    `-W N` = seconds       (iputils ping; integer only)
    Treating macOS as Linux makes -W 2 mean "2 ms" → every reply arrives "out
    of wait time" and ping prints no per-packet line → regex returns None.
    """
    timeout_ms = int(timeout * 1000)
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    logger.debug("ping_ip(%s): exec %s", ip, " ".join(cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
    except subprocess.TimeoutExpired as exc:
        logger.debug("ping_ip(%s): subprocess TIMED OUT after %.1fs", ip, timeout + 1)
        return None
    logger.debug("ping_ip(%s): rc=%d", ip, r.returncode)
    logger.debug("ping_ip(%s): stdout=%r", ip, r.stdout)
    if r.stderr:
        logger.debug("ping_ip(%s): stderr=%r", ip, r.stderr)
    if r.returncode != 0:
        logger.debug("ping_ip(%s): nonzero returncode → returning None", ip)
        return None
    # Prefer per-packet "time=X ms"; fall back to "round-trip ... = min/avg/.../"
    # summary (BSD ping prints stats even when a late reply was "out of wait
    # time" and never got a per-packet line).
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", r.stdout)
    if m:
        ms = float(m.group(1))
        logger.debug("ping_ip(%s): matched per-packet time=%.1fms", ip, ms)
        return ms
    m = re.search(r"min/avg/max(?:/stddev)?\s*=\s*[\d.]+/([\d.]+)/", r.stdout)
    if m:
        ms = float(m.group(1))
        logger.debug("ping_ip(%s): no per-packet line; matched summary avg=%.1fms", ip, ms)
        return ms
    logger.debug("ping_ip(%s): no time/summary regex match in stdout → returning None", ip)
    return None


def ping_relays(
    relays_with_ips,
    *,
    parallelism=_PREFILTER_PARALLELISM,
    max_latency_ms=_PREFILTER_MAX_LATENCY_MS,
    timeout=_PREFILTER_PING_TIMEOUT_S,
):
    """Concurrently ping every (relay_id, ip) pair and return them sorted by
    latency ASC. Relays that timed out, errored, or exceeded `max_latency_ms`
    are excluded — the returned list contains only viable candidates.

    Cuts rotation wall-time hugely: a single batched ICMP round is ~1-2s for
    60+ relays vs. ~20-40s per relay if you connect-and-verify in serial."""
    if not relays_with_ips:
        return []
    results = []
    dropped = []  # (rid, ip, reason) for DEBUG-level visibility into rejections
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallelism) as ex:
        future_to_relay = {
            ex.submit(ping_ip, ip, timeout): (rid, ip) for rid, ip in relays_with_ips
        }
        for fut in concurrent.futures.as_completed(future_to_relay):
            rid, ip = future_to_relay[fut]
            try:
                ms = fut.result()
            except Exception as exc:
                ms = None
                reason = f"ping error: {exc}"
            else:
                reason = "no response (timeout/unreachable)" if ms is None \
                         else f"latency {ms:.1f}ms exceeds {max_latency_ms}ms threshold" \
                              if ms > max_latency_ms else None
            if ms is None or ms > max_latency_ms:
                logger.debug("  ping: %s (%s) DROPPED — %s", rid, ip, reason)
                dropped.append((rid, ip, reason))
                continue
            logger.debug("  ping: %s (%s) = %.1fms", rid, ip, ms)
            results.append((rid, ip, ms))
    results.sort(key=lambda t: t[2])
    logger.debug("  ping summary: %d viable, %d dropped (of %d total)",
                 len(results), len(dropped), len(relays_with_ips))
    return results


def connect_to_server(server_id, connect_timeout=40):
    """Set relay + connect, polling `mullvad status` until Connected. (clip_fixer vpn.py)"""
    r = subprocess.run(["mullvad", "relay", "set", "location", server_id],
                       capture_output=True, text=True, timeout=15)
    if "Relay constraints updated" not in r.stdout:
        return False
    if subprocess.run(["mullvad", "connect"], capture_output=True, text=True, timeout=30).returncode != 0:
        return False
    for _ in range(connect_timeout):
        time.sleep(1)
        status = subprocess.run(["mullvad", "status"], capture_output=True, text=True, timeout=5).stdout
        if "Connected" in status and "Connecting" not in status:
            return True
    return False


def _parse_ping_stats(output):
    """Pull (avg_latency_ms, packet_loss_pct) out of ping(8) summary output.
    Returns (None, None) for any field that couldn't be parsed.

    macOS/Linux: "round-trip min/avg/max/stddev = 11.234/11.789/12.345/0.555 ms"
                 "5 packets transmitted, 5 packets received, 0.0% packet loss"
    Windows:     "Minimum = Xms, Maximum = Yms, Average = Zms"
                 "Lost = N (P% loss)"
    """
    avg_ms = None
    loss_pct = None

    m = re.search(r"min/avg/max(?:/stddev)? = [\d.]+/([\d.]+)/", output)
    if m:
        avg_ms = float(m.group(1))
    else:
        m = re.search(r"Average\s*=\s*(\d+)\s*ms", output)
        if m:
            avg_ms = float(m.group(1))

    m = re.search(r"([\d.]+)%\s*(?:packet\s*)?loss", output)
    if m:
        loss_pct = float(m.group(1))

    return avg_ms, loss_pct


def _default_route_iface_macos():
    """Interface name carrying the default route on macOS (e.g. 'en0'), or None."""
    out = subprocess.run(
        ["route", "-n", "get", "default"],
        capture_output=True, text=True, timeout=5,
    ).stdout
    m = re.search(r"interface:\s*(\S+)", out)
    return m.group(1) if m else None


def _link_is_wifi():
    """Best-effort detection of whether the default-route link is Wi-Fi.

    Returns True (Wi-Fi), False (wired Ethernet), or None (couldn't tell). Used
    to loosen the verify_connection latency ceiling on Wi-Fi, where RTT + jitter
    routinely exceed the wired bar even for perfectly usable relays. Detection is
    best-effort and NEVER raises — on any error it returns None, which callers
    treat as "give it the benefit of the doubt" (i.e. the looser ceiling)."""
    try:
        if sys.platform == "darwin":
            iface = _default_route_iface_macos()
            if not iface:
                return None
            ports = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            current_port = None
            for line in ports.splitlines():
                line = line.strip()
                if line.startswith("Hardware Port:"):
                    current_port = line.split(":", 1)[1].strip()
                elif line.startswith("Device:") and current_port:
                    if line.split(":", 1)[1].strip() == iface:
                        p = current_port.lower()
                        return "wi-fi" in p or "airport" in p
            return None
        if sys.platform == "win32":
            # PhysicalMediaType of the adapter carrying the default route:
            # 'Native802_11' = Wi-Fi, '802.3' = wired Ethernet.
            ps = (
                "$i = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Sort-Object RouteMetric | Select-Object -First 1 "
                "-ExpandProperty InterfaceIndex; "
                "(Get-NetAdapter -InterfaceIndex $i).PhysicalMediaType"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=10,
            ).stdout.strip().lower()
            if "802_11" in out or "wireless" in out:
                return True
            if "802.3" in out or "ethernet" in out:
                return False
            return None
        if sys.platform.startswith("linux"):
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            m = re.search(r"\bdev\s+(\S+)", out)
            if not m:
                return None
            return os.path.isdir(f"/sys/class/net/{m.group(1)}/wireless")
    except Exception as exc:  # best-effort; never break verify_connection
        logger.debug("link-type detection failed: %s", exc)
    return None


def verify_connection(host="google.com"):
    """Ping `host` through the tunnel to confirm the relay is (a) reachable,
    (b) reasonably fast (avg RTT within the latency ceiling: 200ms wired, 350ms
    on Wi-Fi via _link_is_wifi), and (c) not dropping
    packets (loss <= _MAX_PACKET_LOSS_PCT). Returns True iff all three hold.
    The numbers actually measured get logged so a caller can see why a relay
    was rejected. (Extends clip_fixer's binary-pass/fail check with parsing.)

    `host` defaults to google.com (generic reachability test) but callers can
    override to verify against the actual target site (e.g. musescore.com) —
    so the chosen relay is one that REACHES YOUR TARGET, not just one with
    generic internet."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", str(_PING_COUNT), "-w", "5000", host]
    else:
        cmd = ["ping", "-c", str(_PING_COUNT), "-W", "5", host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_PING_COUNT * 5)
    except subprocess.TimeoutExpired:
        logger.info("  ping subprocess timed out")
        return False
    if result.returncode != 0:
        return False
    avg_ms, loss_pct = _parse_ping_stats(result.stdout)
    logger.info("  ping: avg=%s ms, loss=%s%%",
                f"{avg_ms:.1f}" if avg_ms is not None else "?",
                f"{loss_pct:.1f}" if loss_pct is not None else "?")
    wifi = _link_is_wifi()
    # Strict wired ceiling only when we're confident the link is Ethernet; Wi-Fi
    # (or an undetectable link) gets the looser ceiling so normal WiFi jitter
    # doesn't reject otherwise-usable relays.
    max_latency = _MAX_AVG_LATENCY_MS if wifi is False else _WIFI_MAX_AVG_LATENCY_MS
    link = {True: "wifi", False: "ethernet", None: "unknown"}[wifi]
    if avg_ms is not None and avg_ms > max_latency:
        logger.info("  rejecting: avg latency %.1fms > %dms threshold (%s link)",
                    avg_ms, max_latency, link)
        return False
    if loss_pct is not None and loss_pct > _MAX_PACKET_LOSS_PCT:
        logger.info("  rejecting: packet loss %.1f%% > %d%% threshold",
                    loss_pct, _MAX_PACKET_LOSS_PCT)
        return False
    return True


def disconnect():
    """Disconnect from Mullvad. (clip_fixer vpn.py)"""
    try:
        subprocess.run(["mullvad", "disconnect"], check=True, timeout=10, capture_output=True)
        time.sleep(1)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def detection_flags(api="https://api.ipapi.is/", fields=("is_vpn", "is_proxy")):
    """Check the CURRENT (tunneled) exit IP's reputation. Returns (ip, {field: bool})."""
    raw = subprocess.run(["curl", "-s", api], capture_output=True, text=True, timeout=20).stdout
    data = json.loads(raw)
    return data.get("ip", "?"), {f: bool(data.get(f, False)) for f in fields}


def rotate(skip=None, country="us", verify_host="google.com"):
    """Walk the WireGuard relays for `country` (default 'us', pass None for any),
    skipping any in `skip`, and stop at the first one that connects + verifies
    against `verify_host` + isn't flagged by ipapi.is. Returns the new relay id
    on success, or None if every candidate failed.

    Candidates are pre-pinged from outside the tunnel in parallel, then walked
    in RANDOM order — relays that don't respond or exceed _PREFILTER_MAX_LATENCY_MS
    are skipped entirely. The pre-ping is only a viability/latency-ceiling filter;
    we deliberately do NOT walk nearest-first, because always picking the
    lowest-latency exit loosely triangulates our real location and makes the
    rotation pattern predictable. If 0 relays respond to ICMP (likely outbound
    ping blocked), we fall back to attempting all relays in random order — the
    WireGuard handshake does not use ICMP, so connect can still succeed.

    `verify_host` is the in-tunnel ping target used to confirm the relay
    actually works. Default google.com = generic reachability; override with
    e.g. 'musescore.com' to pick relays that reach your actual workload.

    On None, the tunnel is left torn down (disconnect() called)."""
    skip = set(skip) if skip else set()
    relays_w_ips = [(r, ip) for r, ip in list_relays_with_ips(country=country) if r not in skip]
    if not relays_w_ips:
        return None
    logger.info("Pre-pinging %d candidate relay(s) ...", len(relays_w_ips))
    sorted_relays = ping_relays(relays_w_ips)
    if not sorted_relays:
        # ICMP-to-relay-IPs is blocked somewhere (ISP, CGNAT, Mullvad-side
        # rate-limit). Don't give up — the WireGuard handshake doesn't use
        # ICMP, so the connect attempt may still succeed. Walk all candidates
        # in randomized order with NaN as the "unpinged" sentinel.
        logger.warning("  0 relays responded to ICMP (likely outbound ping blocked) — "
                       "falling back to unfiltered list in random order")
        random.shuffle(relays_w_ips)
        sorted_relays = [(rid, ip, float("nan")) for rid, ip in relays_w_ips]
    else:
        # Walk viable relays in RANDOM order, NOT ascending latency. Always
        # connecting to the nearest (lowest-RTT) exit would loosely triangulate
        # our real location and give the rotation a predictable signature; a
        # random walk over all relays under the (loose) ceiling breaks both.
        random.shuffle(sorted_relays)
        logger.info("  %d viable after ping filter (max %.0fms), walking in RANDOM order",
                    len(sorted_relays), _PREFILTER_MAX_LATENCY_MS)
    for server, _ip, pre_ms in sorted_relays:
        pre_label = f"{pre_ms:.0f}ms" if pre_ms == pre_ms else "unpinged"
        logger.info("Checking %s (pre-ping %s) ...", server, pre_label)
        if not connect_to_server(server):
            logger.info("  %s connect failed → next", server)
            continue
        if not verify_connection(host=verify_host):
            logger.info("  %s no connectivity to %s (ping failed) → next",
                        server, verify_host)
            disconnect()
            continue
        try:
            ip, flags = detection_flags()
        except Exception as exc:
            logger.info("  %s detection error (%s) → next", server, exc)
            continue
        hits = [name for name, flagged in flags.items() if flagged]
        if hits:
            logger.info("  %s (%s) DETECTED! → %s", server, ip, ", ".join(hits))
            continue
        logger.info("  %s (%s) clean ✓ — staying connected here, done.", server, ip)
        return server
    disconnect()
    return None


def main():
    p = argparse.ArgumentParser(prog="vpn-anonymizer")
    p.add_argument("-d", "--debug", action="store_true",
                   help="show per-relay ping latency + drop reasons (DEBUG level)")
    p.add_argument("--country", default="us",
                   help="2-letter ISO country code to scan (default us; pass empty for any)")
    p.add_argument("--ping", metavar="HOST", default="google.com",
                   help="host to ping THROUGH the tunnel as the relay verify check. "
                        "Default google.com (generic reachability). Override with your "
                        "actual workload target (e.g. musescore.com) so relays that "
                        "reach google but not your target get rejected.")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(message)s",
    )

    relays = list_relays(country=args.country or None)
    if not relays:
        sys.exit("No relays found — is the mullvad CLI installed and the daemon running?")
    print(f"Found {len(relays)} relays.\n", flush=True)
    if rotate(country=args.country or None, verify_host=args.ping) is None:
        print("No clean relay found.", flush=True)


if __name__ == "__main__":
    main()
