# VPN Anonymizer

Cycles through every Mullvad WireGuard relay, connects to each, ping-verifies the
connection, and checks whether that exit IP is flagged as **VPN / datacenter / proxy**
(via [api.ipapi.is](https://ipapi.is)) — so you can see which relays come up clean.

Connect / ping-verify / disconnect logic is reused from `clip_fixer`'s `scraper/vpn.py`.

## Requirements

- `mullvad` CLI installed and the daemon running
- Logged into a Mullvad account (`mullvad account login <number>`)

## Usage

```bash
python3 vpn_anonymizer.py
```

No arguments. It enumerates all relays and works through them in order, logging
each result. It will churn your network connection as it hops servers, and there
are hundreds of relays, so **Ctrl-C** once you've found enough clean ones.

## Output

```
Found 723 relays.

Checking us-nyc-wg-001 ...
  us-nyc-wg-001 (185.213.155.66) DETECTED! → is_vpn, is_datacenter
Checking us-nyc-wg-002 ...
  us-nyc-wg-002 no connectivity (ping failed) → next
Checking se-got-wg-004 ...
  se-got-wg-004 (193.138.7.x) clean ✓
```
