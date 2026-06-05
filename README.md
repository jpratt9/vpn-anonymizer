# VPN Anonymizer

Cycles through US Mullvad WireGuard relays, connects to each, ping-verifies the
connection, and checks whether that exit IP is flagged as **VPN / proxy**
(via [api.ipapi.is](https://ipapi.is)). It stops at the first clean relay and stays
connected to it.

Connect / ping-verify / disconnect logic is reused from `clip_fixer`'s `scraper/vpn.py`.

## Requirements

- `mullvad` CLI installed and the daemon running
- Logged into a Mullvad account (`mullvad account login <number>`)

## Usage

```bash
python3 vpn_anonymizer.py
```

No arguments. It enumerates the US relays and works through them in order, logging
each result, and **stops at the first clean one** (leaving the VPN connected to it).

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
