#!/usr/bin/env python3
"""Offline tests for v4finder. No network: DNS is stubbed.

    python3 test_v4finder.py

The FCrDNS tiering is the reason this file exists. Its demotion branch cannot
be exercised against the live internet without finding a host whose PTR lies,
so it is tested against a stub resolver instead.
"""

import importlib.util
import ipaddress
import pathlib
import sys

spec = importlib.util.spec_from_file_location(
    "v4finder", pathlib.Path(__file__).with_name("v4finder.py")
)
V = importlib.util.module_from_spec(spec)
sys.modules["v4finder"] = V  # dataclasses resolves annotations via sys.modules
spec.loader.exec_module(V)

FAILURES = []


def check(desc, got, want):
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {desc}")
    if not ok:
        print(f"        got  {got!r}\n        want {want!r}")
        FAILURES.append(desc)


class StubDNS:
    """Answers from a dict; records nothing else. Same API as V.DNS."""

    def __init__(self, ptr=None, a=None, aaaa=None):
        self._ptr, self._a, self._aaaa = ptr or {}, a or {}, aaaa or {}
        self.dnssec_ad = {}

    def ptr(self, ip):
        return list(self._ptr.get(ip, []))

    def a(self, host):
        return list(self._a.get(host, []))

    def aaaa(self, host):
        return list(self._aaaa.get(host, []))


class Opt:
    """Minimal stand-in for the argparse namespace."""

    def __init__(self, **kw):
        self.offline = False
        self.verify = True
        self.timeout = 1.0
        self.max_names = 8
        self.max_netblocks = 10
        self.only = set()
        self.skip = set()
        self.tls = False
        self.tls_ports = [443]
        self.sni = None
        self.public_only = False
        self.rdap_netblocks = False
        self.nat64_prefix = None
        self.sixrd_prefix = None
        self.sixrd_v4_prefix = None
        self.sixrd_v4_masklen = None
        self.workers = 1
        self.trace = False
        self.dns = StubDNS()
        self.__dict__.update(kw)


TARGET = "2001:db8:900d::1"


def fcrdns_case(name, aaaa_for_host):
    """Run one PTR->A finding through verify() and return its tier."""
    a = ipaddress.IPv6Address(TARGET)
    dns = StubDNS(
        ptr={TARGET: ["host.example."], "203.0.113.10": []},
        a={"host.example.": ["203.0.113.10"]},
        aaaa={"host.example.": aaaa_for_host},
    )
    opt = Opt(dns=dns)
    findings = V.s_ptr_forward(a, opt)
    V.verify(findings, a, opt)
    hits = [f for f in findings if f.ipv4 == "203.0.113.10"]
    assert len(hits) == 1, f"{name}: expected exactly one finding, got {len(hits)}"
    return hits[0]


print("FCrDNS tiering (the three branches)")

# 1. Forward-confirmed: the hostname's AAAA includes the target.
f = fcrdns_case("confirmed", [TARGET])
check("AAAA includes target -> 'confirmed'", f.confidence, "confirmed")
check("  ...and is flagged", f.extra.get("forward_confirmed"), True)

# Spelling of the AAAA must not matter.
f = fcrdns_case("confirmed-expanded", ["2001:0db8:900d:0000:0000:0000:0000:0001"])
check("AAAA in expanded form still confirms", f.confidence, "confirmed")

# 2. Contradicted: hostname has AAAA records, none of them the target.
#    This is a PTR pointing somewhere unrelated — the dangerous case.
f = fcrdns_case("demoted", ["2606:4700:4700::1111"])
check("AAAA excludes target -> demoted to 'weak'", f.confidence, "weak")
check("  ...and is flagged false", f.extra.get("forward_confirmed"), False)
check("  ...and says why", "NOT forward-confirmed" in f.evidence, True)

# 3. Unconfirmable: no AAAA at all. Stays strong, but must say so.
f = fcrdns_case("unconfirmable", [])
check("no AAAA -> stays 'strong'", f.confidence, "strong")
check("  ...flagged as unknown", f.extra.get("forward_confirmed"), None)
check("  ...and says why", "unconfirmable" in f.evidence, True)

# 4. The same three branches serve certificate-derived findings. The evidence
#    must name the certificate, not a PTR record that was never consulted.
def san_case(aaaa_for_host):
    a = ipaddress.IPv6Address(TARGET)
    dns = StubDNS(a={"cert.example.": ["203.0.113.20"]},
                  aaaa={"cert.example.": aaaa_for_host},
                  ptr={"203.0.113.20": []})
    opt = Opt(dns=dns)
    f = V.Finding("TLS SAN -> A (port 443)", "strong", "203.0.113.20",
                  "certificate lists cert.example.",
                  extra={"san": "cert.example."})
    V.verify([f], a, opt)
    return f


f = san_case(["2606:4700:4700::1111"])
check("SAN contradicted -> 'weak'", f.confidence, "weak")
check("  ...evidence names the certificate",
      "certificate SAN is stale" in f.evidence, True)
check("  ...and never claims a PTR was checked", "PTR" in f.evidence, False)
f = san_case([TARGET])
check("SAN forward-confirmed -> 'confirmed'", f.confidence, "confirmed")
check("  ...evidence names the certificate",
      "certificate SAN is corroborated" in f.evidence, True)

print("\nTier plumbing")
check("every tier has a sort order", set(V.CONF_COLOR) <= set(V.CONF_ORDER), True)
check("'confirmed' outranks 'deterministic'",
      V.CONF_ORDER["confirmed"] < V.CONF_ORDER["deterministic"], True)
check("'confirmed' is actionable", "confirmed" in V.ACTIONABLE_TIERS, True)
check("'informational' is not actionable",
      "informational" in V.ACTIONABLE_TIERS, False)

print("\nDeterministic extraction (RFC reference vectors)")


def structural(addr, strategy, **kw):
    a = ipaddress.IPv6Address(addr)
    return [f.ipv4 for f in strategy(a, Opt(**kw))]


check("6to4 RFC 3056", structural("2002:c000:0204::1", V.s_6to4), ["192.0.2.4"])
check("Teredo RFC 4380 (client, server)",
      structural("2001:0:4136:e378:8000:63bf:3fff:fdd2", V.s_teredo),
      ["192.0.2.45", "65.54.227.120"])
check("NAT64 well-known /96",
      structural("64:ff9b::c000:221", V.s_nat64), ["192.0.2.33"])
check("NAT64 RFC 8215 /48",
      structural("64:ff9b:1:cb00:71:700::", V.s_nat64), ["203.0.113.7"])
check("ISATAP", structural("2001:db8:1::200:5efe:203.0.113.9", V.s_isatap),
      ["203.0.113.9"])
check("6rd with CIDR v4 prefix",
      structural("2a01:e00:abcd::1", V.s_6rd,
                 sixrd_prefix="2a01:e00::/26", sixrd_v4_prefix="192.0.2.0/24"),
      ["192.0.2.2"])
check("6rd ignores a non-matching address",
      structural("2606:4700::1", V.s_6rd,
                 sixrd_prefix="2a01:e00::/26", sixrd_v4_prefix="192.0.2.0/24"),
      [])
check("no transition encoding -> nothing",
      structural("2a00:1450:4007:80f::200e", V.s_6to4)
      + structural("2a00:1450:4007:80f::200e", V.s_teredo)
      + structural("2a00:1450:4007:80f::200e", V.s_isatap), [])

print("\nInput handling")
check("brackets, zone id and prefix stripped",
      str(V.normalise_input("[2001:DB8::1%eth0]/64")), "2001:db8::1")
for bad in ("garbage", "1.2.3.4", ""):
    try:
        V.normalise_input(bad)
        check(f"{bad!r} rejected", False, True)
    except ValueError:
        check(f"{bad!r} rejected", True, True)

print("\nCLI validation (must reject, not silently ignore)")
for args, why in (
    (["2606:4700:4700::1111", "--only", "ptrr"], "unknown --only strategy"),
    (["2606:4700:4700::1111", "--skip", "nope"], "unknown --skip strategy"),
    (["64:ff9b::1", "--nat64-prefix", "2001:db8::/33"], "bad NAT64 prefix length"),
    (["2a01:e00::1", "--6rd-prefix", "2a01:e00::/26",
      "--6rd-v4-prefix", "192.0.2.0"], "6rd v4 prefix without mask length"),
    (["2606:4700:4700::1111", "--resolver", "not-an-ip"], "bad --resolver"),
    (["2606:4700:4700::1111", "--workers", "0"], "workers < 1"),
):
    try:
        V.main(args)
        check(why, "accepted", "rejected")
    except SystemExit as e:
        check(why, "rejected" if e.code == 2 else f"exit {e.code}", "rejected")

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURE(S): " + "; ".join(FAILURES))
    sys.exit(1)
print("all tests passed")
