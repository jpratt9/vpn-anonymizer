# VPN Anonymizer

> A small tool for staying in touch with loved ones during periods of internet
> censorship or surveillance — cycles through Mullvad's US WireGuard relays
> until you find a clean exit IP that isn't flagged as VPN / proxy.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Cycles through US Mullvad WireGuard relays, connects to each, ping-verifies the
connection, and checks whether that exit IP is flagged as **VPN / proxy**
(via [api.ipapi.is](https://ipapi.is)). It stops at the first clean relay and stays
connected to it — giving you a tunnel that looks like a normal residential
connection to services that otherwise block known VPN exits.

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

new_relay = rotate(skip={"us-nyc-wg-001"})   # returns the new relay id, or None
```

## Output

```
Found 210 relays.

Checking us-nyc-wg-001 ...
  us-nyc-wg-001 (185.213.155.66) DETECTED! → is_vpn
Checking us-nyc-wg-002 ...
  us-nyc-wg-002 no connectivity (ping failed) → next
Checking us-lax-wg-204 ...
  us-lax-wg-204 (198.54.x.x) clean ✓ — staying connected here, done.
```

## License

GPL-3.0 — see [LICENSE](LICENSE). Matches Mullvad's own license; any fork or
derivative must also remain open under GPL-3.0.
