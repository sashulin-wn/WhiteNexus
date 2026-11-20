import unittest
from collections import Counter

import collector as C
import similar as S

UUID = "123e4567-e89b-12d3-a456-426614174000"
PBK_A = "A" * 43
PBK_B = "B" * 43


def make_link(pbk=PBK_A, sid="01234567", host="edge.example.org", port=443, sni="vk.ru", extra=""):
    return (
        f"vless://{UUID}@{host}:{port}?type=tcp&security=reality&pbk={pbk}"
        f"&sid={sid}&sni={sni}&fp=chrome&encryption=none{extra}#test"
    )


class ProjectTests(unittest.TestCase):
    def test_parse_whitelist_reality(self):
        parsed = C.parse_vless(make_link())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["tier"], 1)
        self.assertEqual(parsed["pbk"], PBK_A)

    def test_non_whitelist_sni_is_rejected_by_collect(self):
        self.assertIsNone(C.parse_vless(make_link(sni="example.com")))

    def test_similar_can_read_tls_vless(self):
        link = f"vless://{UUID}@edge.example.org:443?security=tls&type=ws&sni=cdn.example.org&path=%2Fws#tls"
        parsed = C.parse_vless(link, keep_other=True, require_reality=False)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["security"], "tls")
        self.assertIsNotNone(S.features(link))

    def test_reality_options_are_part_of_dedup_key(self):
        first = C.parse_vless(make_link(pbk=PBK_A))
        second = C.parse_vless(make_link(pbk=PBK_B))
        third = C.parse_vless(make_link(pbk=PBK_A, sid="89abcdef"))
        self.assertNotEqual(C.config_key(first), C.config_key(second))
        self.assertNotEqual(C.config_key(first), C.config_key(third))

    def test_xray_and_singbox_config_generation(self):
        parsed = C.parse_vless(make_link())
        parsed["ip"] = "203.0.113.10"
        xray = C._core_config(parsed, 23456, "xray")
        singbox = C._core_config(parsed, 23457, "singbox")
        self.assertIn("inbounds", xray)
        self.assertEqual(xray["outbounds"][0]["protocol"], "vless")
        stream = xray["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["method"], "raw")
        self.assertNotIn("network", stream)
        self.assertIn("rawSettings", stream)
        self.assertEqual(singbox["outbounds"][0]["type"], "vless")
        self.assertTrue(singbox["outbounds"][0]["tls"]["reality"]["enabled"])

    def test_unsupported_singbox_xhttp_is_not_misreported_as_failure(self):
        link = make_link(extra="&type=xhttp&path=%2F")
        parsed = C.parse_vless(link)
        parsed["type"] = "xhttp"
        self.assertIsNone(C._core_config(parsed, 23458, "singbox"))
        self.assertIsNotNone(C._core_config(parsed, 23459, "xray"))

    def test_north_america_share_is_capped(self):
        records = [
            {"id": "de1", "ip": "de1", "rank_key": (1,)},
            {"id": "de2", "ip": "de2", "rank_key": (2,)},
            {"id": "de3", "ip": "de3", "rank_key": (3,)},
            {"id": "us1", "ip": "us1", "rank_key": (4,)},
            {"id": "ca1", "ip": "ca1", "rank_key": (5,)},
        ]
        geo = {"de1": {"countryCode": "DE"}, "de2": {"countryCode": "DE"},
               "de3": {"countryCode": "DE"}, "us1": {"countryCode": "US"},
               "ca1": {"countryCode": "CA"}}
        selected, dropped = C._apply_na_cap(records, 5, geo)
        na = sum(1 for item in selected if item["id"] in {"us1", "ca1"})
        self.assertEqual(na, 1)
        self.assertLessEqual(na / len(selected), 0.25)
        self.assertEqual(dropped, 1)

    def test_similar_known_key_keeps_reality_distinctions(self):
        one = S.features(make_link(pbk=PBK_A))
        two = S.features(make_link(pbk=PBK_B))
        self.assertNotEqual(S.identity_key(one), S.identity_key(two))

    def test_working_domain_hosts_are_resolved_for_subnet_profile(self):
        import unittest.mock as mock
        link = make_link(host="working.example.net")
        with mock.patch.object(C, "resolve", return_value="8.8.8.25"):
            profile, counts, _ = S.build_profile([link], resolver=C.resolve)
        self.assertEqual(profile["subnet"]["8.8.8.0/24"], 1)
        self.assertEqual(counts["working_hosts_resolved"], 1)

    def test_reality_ws_is_not_sent_to_cores_that_do_not_support_it(self):
        parsed = C.parse_vless(make_link(extra="&type=ws"))
        self.assertIsNotNone(parsed)
        self.assertIsNone(C._core_config(parsed, 23460, "xray"))
        self.assertIsNone(C._core_config(parsed, 23461, "singbox"))

    def test_tls_ws_is_supported_by_singbox(self):
        link = f"vless://{UUID}@edge.example.org:443?security=tls&type=ws&sni=cdn.example.org&path=%2Fws#tls"
        parsed = C.parse_vless(link, keep_other=True, require_reality=False)
        parsed["ip"] = "203.0.113.10"
        config = C._core_config(parsed, 23462, "singbox")
        self.assertEqual(config["outbounds"][0]["transport"]["type"], "ws")

    def test_tls_quic_is_supported_by_singbox_but_not_xray(self):
        link = f"vless://{UUID}@edge.example.org:443?security=tls&type=quic&sni=cdn.example.org"
        parsed = C.parse_vless(link, keep_other=True, require_reality=False)
        parsed["ip"] = "203.0.113.10"
        self.assertIsNone(C._core_config(parsed, 23463, "xray"))
        config = C._core_config(parsed, 23464, "singbox")
        self.assertEqual(config["outbounds"][0]["transport"]["type"], "quic")

    def test_unknown_geo_uses_conservative_quota(self):
        records = [
            {"id": "de1", "ip": "de1", "rank_key": (1,)},
            {"id": "de2", "ip": "de2", "rank_key": (2,)},
            {"id": "de3", "ip": "de3", "rank_key": (3,)},
            {"id": "unknown", "ip": "unknown", "rank_key": (4,)},
        ]
        geo = {key: {"countryCode": "DE"} for key in ("de1", "de2", "de3")}
        selected, dropped = C._apply_na_cap(records, 4, geo)
        self.assertEqual(len(selected), 4)
        self.assertEqual(dropped, 0)
        # Unknown is allowed only at the same capped rate as potential US/CA entries.
        restricted = sum(1 for item in selected if not C._country_code(item, geo))
        self.assertLessEqual(restricted / len(selected), 0.25)

    def test_xray_does_not_use_removed_http_h2_transport(self):
        link = f"vless://{UUID}@edge.example.org:443?security=tls&type=h2&sni=cdn.example.org"
        parsed = C.parse_vless(link, keep_other=True, require_reality=False)
        parsed["ip"] = "203.0.113.10"
        self.assertIsNone(C._core_config(parsed, 23460, "xray"))
        self.assertIsNotNone(C._core_config(parsed, 23461, "singbox"))

    def test_similar_caps_each_sni_family_and_subnet(self):
        items = []
        geo = {}
        for index in range(20):
            ip = f"203.0.113.{index + 1}"
            items.append({
                "base": f"vless://candidate-{index}", "ip": ip, "host": f"node{index}.different-domain-{index}.net",
                "families": ["shared-sni.example.org"], "subnet": f"198.51.{index}.0/24",
                "pbk": f"key-{index}", "rank_key": (index,), "xray_ok": False, "singbox_ok": False,
                "verified": False, "strong": 20.0, "soft": 0.0, "ms": float(index),
            })
            geo[ip] = {"countryCode": "DE"}
        stats = Counter()
        selected, dropped = S._apply_final_caps(items, geo, stats)
        self.assertEqual(len(selected), S.MAX_PER_FAMILY)
        self.assertEqual(dropped, 0)
        self.assertEqual(stats["dropped_per_family"], 5)

    def test_country_fallback_uses_exit_ip_geo_not_entry_ip(self):
        candidate = {"ip": "198.51.100.10", "exit_ip": "203.0.113.20", "exit_cc": ""}
        geo = {
            "198.51.100.10": {"countryCode": "US"},
            "203.0.113.20": {"countryCode": "DE"},
        }
        self.assertEqual(C._country_code(candidate, geo), "DE")

    def test_ipv6_subnet_is_grouped_by_64(self):
        self.assertEqual(S.subnet24("2001:db8:abcd:1234::1"), "2001:db8:abcd:1234::/64")

    def test_registered_domain_uses_public_suffix(self):
        self.assertEqual(C.registered_domain("api.store.example.co.uk"), "example.co.uk")


if __name__ == "__main__":
    unittest.main(verbosity=2)
