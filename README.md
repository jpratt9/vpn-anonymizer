# VPN Anonymizer

> A small tool for staying in touch with loved ones during periods of internet
> censorship or surveillance — cycles through Mullvad's US WireGuard relays
> until you find a clean exit IP that isn't flagged as VPN / proxy.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Cycles through Mullvad WireGuard relays, connects to each, **measures latency
and packet loss** through the tunnel, and checks whether that exit IP is
flagged as **VPN / proxy** (via [api.ipapi.is](https://ipapi.is)). It stops at
the first relay that's reachable, fast enough (default avg RTT ≤ 200 ms),
reliable enough (default packet loss ≤ 20%), and not detected — giving you a
tunnel that looks like a normal residential connection to services that
otherwise block known VPN exits.

## Requirements

- [`mullvad`](https://mullvad.net/en/download) CLI installed and the daemon running
- Logged into a Mullvad account (`mullvad account login <number>`)
- Python 3.10+

## Install

```bash
pip install git+https://github.com/jpratt9/vpn-anonymizer.git
```

## Usage

CLI:

```bash
vpn-anonymizer
```

As a library:

```python
from vpn_anonymizer import rotate

new_relay = rotate(skip={"us-nyc-wg-001"})           # US relays only (default)
new_relay = rotate(skip=..., country=None)           # all countries
new_relay = rotate(skip=..., country="se")           # Sweden only
```

## Output

```
Found 210 relays.

Checking us-nyc-wg-001 ...
  us-nyc-wg-001 (185.213.155.66) DETECTED! → is_vpn
Checking us-nyc-wg-002 ...
  ping: avg=? ms, loss=100.0%
  us-nyc-wg-002 no connectivity (ping failed) → next
Checking us-sea-wg-101 ...
  ping: avg=287.3 ms, loss=0.0%
  rejecting: avg latency 287.3ms > 200ms threshold
Checking us-lax-wg-204 ...
  ping: avg=42.1 ms, loss=0.0%
  us-lax-wg-204 (198.54.x.x) clean ✓ — staying connected here, done.
```

## Tuning

Defaults are conservative — adjust the constants at the top of
[`vpn_anonymizer.py`](vpn_anonymizer.py) if you need different thresholds:

| constant | default | meaning |
|---|---|---|
| `_PING_COUNT` | 5 | packets sent per relay (more → better stats, slower) |
| `_MAX_AVG_LATENCY_MS` | 200 | reject relays whose average RTT exceeds this |
| `_MAX_PACKET_LOSS_PCT` | 20 | reject relays losing more than this fraction |

## License

GPL-3.0 — see [LICENSE](LICENSE). Matches Mullvad's own license; any fork or
derivative must also remain open under GPL-3.0.
