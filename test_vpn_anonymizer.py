"""Unit tests for vpn_anonymizer. All subprocess (mullvad CLI + curl) calls are
mocked — nothing real is contacted and no VPN connection is made."""
import json
import unittest
from unittest import mock

import vpn_anonymizer as va


def fake_proc(stdout="", returncode=0):
    return mock.Mock(stdout=stdout, returncode=returncode)


# A trimmed `mullvad relay list` sample: US WireGuard, US OpenVPN, and a non-US relay.
RELAY_LIST = """\
USA (us)
\tNew York City, NY (nyc)
\t\tus-nyc-wg-001 (185.213.155.66) - WireGuard
\t\tus-nyc-wg-002 (185.213.155.67) - WireGuard
\t\tus-nyc-ovpn-001 (185.213.155.68) - OpenVPN
\tLos Angeles, CA (lax)
\t\tus-lax-wg-201 (198.54.0.1) - WireGuard
Sweden (se)
\tGothenburg (got)
\t\tse-got-wg-001 (193.138.7.1) - WireGuard
"""


class TestListRelays(unittest.TestCase):
    def test_only_us_wireguard(self):
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=RELAY_LIST)):
            self.assertEqual(
                va.list_relays(),
                ["us-nyc-wg-001", "us-nyc-wg-002", "us-lax-wg-201"],
            )  # excludes OpenVPN and non-US relays

    def test_explicit_country_filter(self):
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=RELAY_LIST)):
            self.assertEqual(va.list_relays(country="se"), ["se-got-wg-001"])

    def test_country_none_returns_all_wireguard_relays(self):
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=RELAY_LIST)):
            self.assertEqual(
                va.list_relays(country=None),
                ["us-nyc-wg-001", "us-nyc-wg-002", "us-lax-wg-201", "se-got-wg-001"],
            )


_MACOS_PING_OK = """\
PING google.com (142.250.31.139): 56 data bytes
64 bytes from 142.250.31.139: icmp_seq=0 ttl=109 time=12.345 ms
64 bytes from 142.250.31.139: icmp_seq=1 ttl=109 time=11.234 ms
64 bytes from 142.250.31.139: icmp_seq=2 ttl=109 time=13.111 ms
64 bytes from 142.250.31.139: icmp_seq=3 ttl=109 time=12.000 ms
64 bytes from 142.250.31.139: icmp_seq=4 ttl=109 time=11.500 ms

--- google.com ping statistics ---
5 packets transmitted, 5 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 11.234/12.038/13.111/0.620 ms
"""

_MACOS_PING_SLOW = _MACOS_PING_OK.replace(
    "round-trip min/avg/max/stddev = 11.234/12.038/13.111/0.620 ms",
    "round-trip min/avg/max/stddev = 250.000/350.500/450.000/80.000 ms",
)
_MACOS_PING_LOSSY = """\
PING google.com (142.250.31.139): 56 data bytes
64 bytes from 142.250.31.139: icmp_seq=0 ttl=109 time=12.345 ms

--- google.com ping statistics ---
5 packets transmitted, 1 packets received, 80.0% packet loss
round-trip min/avg/max/stddev = 12.345/12.345/12.345/0.000 ms
"""
_WIN_PING_OK = """\
Pinging google.com [142.250.31.139] with 32 bytes of data:
Reply from 142.250.31.139: bytes=32 time=15ms TTL=109

Ping statistics for 142.250.31.139:
    Packets: Sent = 5, Received = 5, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 12ms, Maximum = 18ms, Average = 14ms
"""


class TestParsePingStats(unittest.TestCase):
    def test_macos_clean(self):
        self.assertEqual(va._parse_ping_stats(_MACOS_PING_OK), (12.038, 0.0))

    def test_macos_lossy(self):
        avg, loss = va._parse_ping_stats(_MACOS_PING_LOSSY)
        self.assertAlmostEqual(avg, 12.345, places=2)
        self.assertEqual(loss, 80.0)

    def test_windows_format(self):
        self.assertEqual(va._parse_ping_stats(_WIN_PING_OK), (14.0, 0.0))

    def test_unparseable_returns_nones(self):
        self.assertEqual(va._parse_ping_stats("garbage"), (None, None))


class TestVerifyConnection(unittest.TestCase):
    def _patch_run(self, stdout, returncode=0):
        return mock.patch.object(
            va.subprocess, "run",
            return_value=fake_proc(stdout=stdout, returncode=returncode),
        )

    def test_fast_clean_relay_accepted(self):
        with self._patch_run(_MACOS_PING_OK):
            self.assertTrue(va.verify_connection())

    def test_high_latency_rejected(self):
        with self._patch_run(_MACOS_PING_SLOW):
            self.assertFalse(va.verify_connection())  # 350ms > 200ms threshold

    def test_high_packet_loss_rejected(self):
        with self._patch_run(_MACOS_PING_LOSSY):
            self.assertFalse(va.verify_connection())  # 80% > 20% threshold

    def test_nonzero_returncode_rejected_without_parsing(self):
        with self._patch_run("", returncode=1):
            self.assertFalse(va.verify_connection())

    def test_ping_subprocess_timeout_rejected(self):
        import subprocess as _sub
        with mock.patch.object(
            va.subprocess, "run",
            side_effect=_sub.TimeoutExpired(cmd="ping", timeout=25),
        ):
            self.assertFalse(va.verify_connection())

    def test_unparseable_output_still_accepted_when_returncode_zero(self):
        # If ping exits 0 but the summary line is missing (truncated output, etc.)
        # we fall back to trusting the exit code — same as the old behavior.
        with self._patch_run("garbage output"):
            self.assertTrue(va.verify_connection())


class TestDetectionFlags(unittest.TestCase):
    def test_excludes_datacenter_keeps_vpn_and_proxy(self):
        payload = json.dumps({"ip": "1.2.3.4", "is_vpn": True, "is_datacenter": True, "is_proxy": False})
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=payload)):
            ip, flags = va.detection_flags()
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(flags, {"is_vpn": True, "is_proxy": False})
        self.assertNotIn("is_datacenter", flags)


def _mock_ping_sort(*relays_w_ips):
    """Build a fake ping_relays() return value preserving input order with
    monotonically increasing latencies."""
    return [(rid, ip, 10.0 + i) for i, (rid, ip) in enumerate(relays_w_ips)]


class TestMainStopOnClean(unittest.TestCase):
    def test_stops_at_first_clean_and_stays_connected(self):
        with mock.patch.object(va, "list_relays", return_value=["us-a-wg-1", "us-b-wg-2", "us-c-wg-3"]), \
             mock.patch.object(va, "list_relays_with_ips", return_value=[
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"), ("us-c-wg-3", "3.3.3.3"),
             ]), \
             mock.patch.object(va, "ping_relays", return_value=_mock_ping_sort(
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"), ("us-c-wg-3", "3.3.3.3"),
             )), \
             mock.patch.object(va, "connect_to_server", return_value=True) as connect, \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", side_effect=[
                 ("1.1.1.1", {"is_vpn": True, "is_proxy": False}),    # flagged -> keep going
                 ("2.2.2.2", {"is_vpn": False, "is_proxy": False}),   # clean  -> stop here
             ]) as detect, \
             mock.patch.object(va, "disconnect") as disconnect, \
             mock.patch("builtins.print"):
            va.main()
        self.assertEqual(connect.call_count, 2)   # third relay never tried
        self.assertEqual(detect.call_count, 2)
        disconnect.assert_not_called()            # stays connected to the clean relay

    def test_no_clean_relay_disconnects_at_end(self):
        with mock.patch.object(va, "list_relays", return_value=["us-a-wg-1", "us-b-wg-2"]), \
             mock.patch.object(va, "list_relays_with_ips", return_value=[
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"),
             ]), \
             mock.patch.object(va, "ping_relays", return_value=_mock_ping_sort(
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"),
             )), \
             mock.patch.object(va, "connect_to_server", return_value=True), \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", side_effect=[
                 ("1.1.1.1", {"is_vpn": True, "is_proxy": False}),
                 ("2.2.2.2", {"is_vpn": False, "is_proxy": True}),
             ]) as detect, \
             mock.patch.object(va, "disconnect") as disconnect, \
             mock.patch("builtins.print"):
            va.main()
        self.assertEqual(detect.call_count, 2)
        disconnect.assert_called_once()           # exhausted -> tear down


class TestRotate(unittest.TestCase):
    def test_returns_relay_id_when_clean_found(self):
        with mock.patch.object(va, "list_relays_with_ips", return_value=[("us-a-wg-1", "1.1.1.1")]), \
             mock.patch.object(va, "ping_relays", return_value=_mock_ping_sort(("us-a-wg-1", "1.1.1.1"))), \
             mock.patch.object(va, "connect_to_server", return_value=True), \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", return_value=("1.1.1.1", {"is_vpn": False, "is_proxy": False})), \
             mock.patch.object(va, "disconnect") as disconnect:
            result = va.rotate()
        self.assertEqual(result, "us-a-wg-1")
        disconnect.assert_not_called()

    def test_returns_none_when_all_flagged_and_disconnects(self):
        with mock.patch.object(va, "list_relays_with_ips", return_value=[
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"),
             ]), \
             mock.patch.object(va, "ping_relays", return_value=_mock_ping_sort(
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"),
             )), \
             mock.patch.object(va, "connect_to_server", return_value=True), \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", return_value=("1.1.1.1", {"is_vpn": True, "is_proxy": False})), \
             mock.patch.object(va, "disconnect") as disconnect:
            result = va.rotate()
        self.assertIsNone(result)
        disconnect.assert_called_once()

    def test_skip_excludes_relays(self):
        seen = []
        def fake_connect(server):
            seen.append(server)
            return True
        all_relays = [("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"), ("us-c-wg-3", "3.3.3.3")]
        # ping_relays is called AFTER the skip filter, so it sees only the unskipped relays.
        # Use side_effect=lambda so the mock returns the actually-passed list.
        with mock.patch.object(va, "list_relays_with_ips", return_value=all_relays), \
             mock.patch.object(va, "ping_relays",
                               side_effect=lambda rs: _mock_ping_sort(*rs)), \
             mock.patch.object(va, "connect_to_server", side_effect=fake_connect), \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", return_value=("1.1.1.1", {"is_vpn": False, "is_proxy": False})), \
             mock.patch.object(va, "disconnect"):
            va.rotate(skip={"us-a-wg-1", "us-b-wg-2"})
        self.assertEqual(seen, ["us-c-wg-3"])  # only the un-skipped one was tried

    def test_walks_in_ping_sorted_order_not_input_order(self):
        # Verify that rotate() respects the ping_relays sort order, not the
        # raw list_relays_with_ips order. ping_relays returns the SLOWEST
        # first here (descending), so connect_to_server should see them
        # in that exact reversed order.
        seen = []
        def fake_connect(server):
            seen.append(server)
            return False  # never settle, force walking all
        all_relays = [("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"), ("us-c-wg-3", "3.3.3.3")]
        with mock.patch.object(va, "list_relays_with_ips", return_value=all_relays), \
             mock.patch.object(va, "ping_relays", return_value=[
                 ("us-c-wg-3", "3.3.3.3", 30.0),
                 ("us-a-wg-1", "1.1.1.1", 50.0),
                 ("us-b-wg-2", "2.2.2.2", 80.0),
             ]), \
             mock.patch.object(va, "connect_to_server", side_effect=fake_connect), \
             mock.patch.object(va, "disconnect"):
            va.rotate()
        self.assertEqual(seen, ["us-c-wg-3", "us-a-wg-1", "us-b-wg-2"])

    def test_country_kwarg_passed_through_to_list_relays_with_ips(self):
        with mock.patch.object(va, "list_relays_with_ips", return_value=[]) as lr, \
             mock.patch.object(va, "disconnect"):
            va.rotate(country=None)
        lr.assert_called_once_with(country=None)

    def test_returns_none_when_ping_filter_drops_everything(self):
        # Every relay either times out (None latency) or exceeds the threshold —
        # ping_relays returns empty, rotate should return None without
        # attempting any connect_to_server calls.
        with mock.patch.object(va, "list_relays_with_ips", return_value=[
                 ("us-a-wg-1", "1.1.1.1"), ("us-b-wg-2", "2.2.2.2"),
             ]), \
             mock.patch.object(va, "ping_relays", return_value=[]), \
             mock.patch.object(va, "connect_to_server") as connect, \
             mock.patch.object(va, "disconnect") as disconnect:
            result = va.rotate()
        self.assertIsNone(result)
        connect.assert_not_called()
        disconnect.assert_called_once()


class TestListRelaysWithIps(unittest.TestCase):
    def test_extracts_id_and_ip_pairs(self):
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=RELAY_LIST)):
            self.assertEqual(
                va.list_relays_with_ips(),
                [("us-nyc-wg-001", "185.213.155.66"),
                 ("us-nyc-wg-002", "185.213.155.67"),
                 ("us-lax-wg-201", "198.54.0.1")],
            )

    def test_country_none_returns_all(self):
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=RELAY_LIST)):
            pairs = va.list_relays_with_ips(country=None)
        self.assertIn(("se-got-wg-001", "193.138.7.1"), pairs)
        self.assertEqual(len(pairs), 4)


class TestPingIp(unittest.TestCase):
    def test_extracts_latency_on_success(self):
        macos_out = ("PING 1.1.1.1 (1.1.1.1): 56 data bytes\n"
                     "64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=12.345 ms\n")
        with mock.patch.object(va.subprocess, "run",
                               return_value=fake_proc(stdout=macos_out)):
            self.assertEqual(va.ping_ip("1.1.1.1"), 12.345)

    def test_returns_none_on_nonzero_exit(self):
        with mock.patch.object(va.subprocess, "run",
                               return_value=fake_proc(stdout="", returncode=1)):
            self.assertIsNone(va.ping_ip("1.1.1.1"))

    def test_returns_none_on_subprocess_timeout(self):
        import subprocess as _sub
        with mock.patch.object(va.subprocess, "run",
                               side_effect=_sub.TimeoutExpired(cmd="ping", timeout=2)):
            self.assertIsNone(va.ping_ip("1.1.1.1"))


class TestPingRelays(unittest.TestCase):
    def test_sorts_ascending_and_drops_unreachable_and_above_threshold(self):
        # Three relays: one fast, one slow-but-under-threshold, one over.
        latencies = {"1.1.1.1": 50.0, "2.2.2.2": 200.0, "3.3.3.3": 9000.0, "4.4.4.4": None}
        with mock.patch.object(va, "ping_ip", side_effect=lambda ip, timeout=2.0: latencies[ip]):
            out = va.ping_relays(
                [("a", "1.1.1.1"), ("b", "2.2.2.2"), ("c", "3.3.3.3"), ("d", "4.4.4.4")],
                max_latency_ms=400,
            )
        # Sorted ASC, "c" and "d" dropped (too slow / unreachable)
        self.assertEqual([(rid, ip) for rid, ip, _ in out],
                         [("a", "1.1.1.1"), ("b", "2.2.2.2")])
        self.assertEqual([ms for _, _, ms in out], [50.0, 200.0])

    def test_empty_input_returns_empty(self):
        self.assertEqual(va.ping_relays([]), [])


if __name__ == "__main__":
    unittest.main()
