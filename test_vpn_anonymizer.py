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


class TestDetectionFlags(unittest.TestCase):
    def test_excludes_datacenter_keeps_vpn_and_proxy(self):
        payload = json.dumps({"ip": "1.2.3.4", "is_vpn": True, "is_datacenter": True, "is_proxy": False})
        with mock.patch.object(va.subprocess, "run", return_value=fake_proc(stdout=payload)):
            ip, flags = va.detection_flags()
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(flags, {"is_vpn": True, "is_proxy": False})
        self.assertNotIn("is_datacenter", flags)


class TestMainStopOnClean(unittest.TestCase):
    def test_stops_at_first_clean_and_stays_connected(self):
        with mock.patch.object(va, "list_relays", return_value=["us-a-wg-1", "us-b-wg-2", "us-c-wg-3"]), \
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
        with mock.patch.object(va, "list_relays", return_value=["us-a-wg-1"]), \
             mock.patch.object(va, "connect_to_server", return_value=True), \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", return_value=("1.1.1.1", {"is_vpn": False, "is_proxy": False})), \
             mock.patch.object(va, "disconnect") as disconnect:
            result = va.rotate()
        self.assertEqual(result, "us-a-wg-1")
        disconnect.assert_not_called()

    def test_returns_none_when_all_flagged_and_disconnects(self):
        with mock.patch.object(va, "list_relays", return_value=["us-a-wg-1", "us-b-wg-2"]), \
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
        with mock.patch.object(va, "list_relays", return_value=["us-a-wg-1", "us-b-wg-2", "us-c-wg-3"]), \
             mock.patch.object(va, "connect_to_server", side_effect=fake_connect), \
             mock.patch.object(va, "verify_connection", return_value=True), \
             mock.patch.object(va, "detection_flags", return_value=("1.1.1.1", {"is_vpn": False, "is_proxy": False})), \
             mock.patch.object(va, "disconnect"):
            va.rotate(skip={"us-a-wg-1", "us-b-wg-2"})
        self.assertEqual(seen, ["us-c-wg-3"])  # only the un-skipped one was tried

    def test_country_kwarg_passed_through_to_list_relays(self):
        with mock.patch.object(va, "list_relays", return_value=[]) as lr, \
             mock.patch.object(va, "disconnect"):
            va.rotate(country=None)
        lr.assert_called_once_with(country=None)


if __name__ == "__main__":
    unittest.main()
