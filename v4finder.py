#!/usr/bin/env python3
"""
V4Finder (v4finder) — derive or discover the public IPv4 address(es)
associated with a public IPv6 address.

Design principle: this tool NEVER guesses. Every result carries a method,
a confidence tier and the evidence it was derived from. For an ordinary
residential or mobile IPv6 address with no PTR record and no transition
mechanism encoded in it, there is simply no IPv4 to derive — and the tool
says so explicitly instead of inventing one.

Confidence tiers
  confirmed     : forward-confirmed. The hostname's own AAAA points back at the
                  target, so the PTR is not merely someone's unilateral claim.
  deterministic : the IPv4 is mathematically embedded in the IPv6 address
                  (6to4, Teredo, NAT64/RFC6052, ISATAP, 6rd, v4-mapped)
  strong        : the same host answers on both families, but the hostname has
                  no AAAA to confirm it against (PTR -> A, TLS SAN -> A)
  weak          : same organisation, or a PTR contradicted by its own AAAA.
                  Context only. Never "the" IPv4.


"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from typing import Any, Callable

__version__ = "2.0.0"

# --------------------------------------------------------------------------
# Optional dependencies — the tool is fully functional without any of them.
# --------------------------------------------------------------------------
try:
    import dns.flags  # type: ignore
    import dns.resolver  # type: ignore
    import dns.reversename  # type: ignore

    HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    HAVE_DNSPYTHON = False

try:
    import requests  # type: ignore

    HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    HAVE_REQUESTS = False

try:
    from cryptography import x509  # type: ignore
    from cryptography.x509.oid import ExtensionOID  # type: ignore

    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


# --------------------------------------------------------------------------
# Presentation
# --------------------------------------------------------------------------
BANNER = r"""
__     ___  _   _____ _           _
\ \   / / || | |  ___(_)_ __   __| | ___ _ __
 \ \ / /| || |_| |_  | | '_ \ / _` |/ _ \ '__|
  \ V / |__   _|  _| | | | | | (_| |  __/ |
   \_/     |_| |_|   |_|_| |_|\__,_|\___|_|
"""

TAGLINE = "  IPv6 -> IPv4 resolver  ::  evidence-based, never a guess"


class C:
    """ANSI colours, auto-disabled when not a TTY or NO_COLOR is set."""

    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    @classmethod
    def _w(cls, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s

    @classmethod
    def green(cls, s: str) -> str:
        return cls._w("32", s)

    @classmethod
    def yellow(cls, s: str) -> str:
        return cls._w("33", s)

    @classmethod
    def red(cls, s: str) -> str:
        return cls._w("31", s)

    @classmethod
    def cyan(cls, s: str) -> str:
        return cls._w("36", s)

    @classmethod
    def dim(cls, s: str) -> str:
        return cls._w("2", s)

    @classmethod
    def bold(cls, s: str) -> str:
        return cls._w("1", s)


CONF_ORDER = {"confirmed": 0, "deterministic": 1, "strong": 2, "weak": 3, "informational": 4}
ACTIONABLE_TIERS = {"confirmed", "deterministic", "strong", "weak"}
CONF_COLOR = {
    "confirmed": C.green,
    "deterministic": C.green,
    "strong": C.cyan,
    "weak": C.yellow,
    "informational": C.dim,
}


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------
@dataclass
class Finding:
    method: str
    confidence: str  # confirmed | deterministic | strong | weak | informational
    ipv4: str | None  # a single address, or a CIDR for weak netblock hits
    evidence: str
    routable: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple[int, int, int, str, str]:
        # tier, then reverse-confirmed first, then routable first
        confirmed = 0 if self.extra.get("reverse_confirmed") is True else 1
        return (
            CONF_ORDER.get(self.confidence, 9),
            confirmed,
            0 if self.routable else 1,
            self.method,
            self.ipv4 or "",
        )

    def dedup_key(self) -> tuple[str, str]:
        return (self.method, self.ipv4 or "")


@dataclass
class Notice:
    level: str  # info | warn | error
    text: str


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------
def normalise_input(raw: str) -> ipaddress.IPv6Address:
    """Accept [2001:db8::1], 2001:db8::1/64, 2001:db8::1%eth0, uppercase, spaces."""
    s = raw.strip()
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]
    s = s.split("/")[0]  # drop any prefix length
    s = s.split("%")[0]  # drop any zone id
    try:
        addr = ipaddress.ip_address(s)
    except ValueError as exc:
        raise ValueError(f"not a valid IP address: {raw!r}") from exc
    if isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(f"{addr} is already an IPv4 address — nothing to resolve")
    return addr


def classify_scope(a: ipaddress.IPv6Address) -> list[Notice]:
    """Warn loudly when the input is not a public/global address."""
    out: list[Notice] = []
    if a.is_loopback:
        out.append(Notice("error", "loopback address (::1) — not a public address"))
    elif a.is_link_local:
        out.append(Notice("error", "link-local (fe80::/10) — not a public address"))
    elif a.is_multicast:
        out.append(Notice("error", "multicast (ff00::/8) — not a host address"))
    elif _in(a, "2002::/16"):
        out.append(Notice("info", "6to4 transition address (2002::/16)"))
    elif _in(a, "2001::/32"):
        out.append(Notice("info", "Teredo transition address (2001::/32)"))
    elif _in(a, "64:ff9b::/96") or _in(a, "64:ff9b:1::/48"):
        out.append(Notice("info", "NAT64 translation address"))
    elif _in(a, "2001:db8::/32"):
        out.append(Notice("warn", "documentation prefix (2001:db8::/32) — not a real host"))
    elif _in(a, "fc00::/7"):
        out.append(Notice("warn", "unique local address (fc00::/7) — not publicly routable"))
    elif a.is_private and not a.ipv4_mapped:
        out.append(Notice("warn", "reserved / non-global address space"))
    if a.is_site_local:
        out.append(Notice("warn", "deprecated site-local address (fec0::/10)"))
    return out


def _in(a: ipaddress.IPv6Address, net: str) -> bool:
    return a in ipaddress.ip_network(net)


def _valid_public_v4(text: str) -> bool:
    try:
        v4 = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return v4.is_global


# --------------------------------------------------------------------------
# Strategy 1..6 — deterministic, structural (offline, zero network)
# --------------------------------------------------------------------------
def s_ipv4_mapped(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """::ffff:a.b.c.d and the deprecated ::a.b.c.d — local representations."""
    out = []
    if a.ipv4_mapped is not None:
        out.append(
            Finding(
                "ipv4-mapped (::ffff:0:0/96)",
                "deterministic",
                str(a.ipv4_mapped),
                f"{a} is the IPv4-mapped representation of {a.ipv4_mapped}",
                routable=False,
                extra={
                    "note": "a local representation of an IPv4 socket, "
                    "not a routable IPv6 address"
                },
            )
        )
    compat = getattr(a, "ipv4_compat", None) if hasattr(a, "ipv4_compat") else None
    if compat is None and _in(a, "::/96") and int(a) > 1:
        compat = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
    if compat is not None:
        out.append(
            Finding(
                "ipv4-compatible (::/96, deprecated)",
                "deterministic",
                str(compat),
                f"{a} embeds {compat} in its low 32 bits (RFC 4291 §2.5.5.1)",
                routable=False,
                extra={"note": "deprecated mechanism, kept for completeness"},
            )
        )
    return out


def s_6to4(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """2002::/16 — the IPv4 is bits 16..47 of the address."""
    v4 = a.sixtofour
    if v4 is None:
        return []
    return [
        Finding(
            "6to4 (2002::/16, RFC 3056)",
            "deterministic",
            str(v4),
            f"bits 16-47 of {a} encode {v4} — this is the 6to4 relay endpoint, "
            "i.e. the host's own public IPv4",
            extra={"public_ipv4": bool(v4.is_global)},
        )
    ]


def s_teredo(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """2001::/32 — carries both the Teredo server and the client's public IPv4."""
    t = a.teredo
    if t is None:
        return []
    server, client = t
    findings = [
        Finding(
            "Teredo client (2001::/32, RFC 4380)",
            "deterministic",
            str(client),
            f"low 32 bits of {a} XOR 0xffffffff = {client} — the public IPv4 of "
            "the NAT the Teredo client sits behind",
        ),
        Finding(
            "Teredo server (2001::/32, RFC 4380)",
            "deterministic",
            str(server),
            f"bits 32-63 of {a} = {server} — the Teredo server, not the host",
            extra={"note": "infrastructure address, not the target host"},
        ),
    ]
    # The UDP port is also recoverable and is genuinely useful context.
    port = ~(int(a) >> 32) & 0xFFFF
    findings[0].extra["nat_udp_port"] = port
    return findings


def s_isatap(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """Any prefix with an interface id of ....:0000:5efe:a.b.c.d or ....:0200:5efe:..."""
    iid = int(a) & 0xFFFFFFFFFFFFFFFF
    marker = (iid >> 32) & 0xFFFFFFFF
    if marker not in (0x00005EFE, 0x02005EFE):
        return []
    v4 = ipaddress.IPv4Address(iid & 0xFFFFFFFF)
    globally_unique = marker == 0x02005EFE
    return [
        Finding(
            "ISATAP (RFC 5214)",
            "deterministic",
            str(v4),
            f"interface identifier {marker:08x}:{v4} — ISATAP embeds the host's "
            f"IPv4 ({'globally unique' if globally_unique else 'private'} u/g bit)",
            extra={"globally_unique": globally_unique},
        )
    ]


_RFC6052_LENS = (32, 40, 48, 56, 64, 96)


def _rfc6052_extract(a: ipaddress.IPv6Address, plen: int) -> ipaddress.IPv4Address | None:
    """RFC 6052 §2.2 — pull the 32 embedded bits, skipping the reserved u octet."""
    if plen not in _RFC6052_LENS:
        return None
    b = a.packed
    if plen < 96 and b[8] != 0:
        return None  # bits 64-71 MUST be zero
    tail = bytes(x for i, x in enumerate(b) if i >= plen // 8 and i != 8)
    if len(tail) < 4:
        return None
    return ipaddress.IPv4Address(tail[:4])


def s_nat64(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """Well-known NAT64 prefixes plus any user-supplied network-specific prefix."""
    out: list[Finding] = []
    for net, label in (
        ("64:ff9b::/96", "well-known NAT64 prefix (RFC 6052)"),
        ("64:ff9b:1::/48", "local-use NAT64 prefix (RFC 8215)"),
    ):
        n = ipaddress.ip_network(net)
        if a in n:
            v4 = _rfc6052_extract(a, n.prefixlen)
            if v4:
                out.append(
                    Finding(
                        f"NAT64 — {label}",
                        "deterministic",
                        str(v4),
                        f"{a} is inside {net}; RFC 6052 extraction yields {v4} "
                        "(the IPv4 destination being translated to)",
                        extra={
                            "note": "this is the IPv4 the traffic is going TO, "
                            "not the IPv6 host's own address"
                        },
                    )
                )
    if opt.nat64_prefix:
        try:
            n = ipaddress.ip_network(opt.nat64_prefix, strict=False)
        except ValueError:
            return out
        if n.version == 6 and a in n:
            v4 = _rfc6052_extract(a, n.prefixlen)
            if v4:
                out.append(
                    Finding(
                        "NAT64 — network-specific prefix (RFC 6052)",
                        "deterministic",
                        str(v4),
                        f"user-supplied NSP {n} applied to {a} yields {v4}",
                    )
                )
    return out


def s_6rd(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """6rd (RFC 5969) — needs ISP-specific parameters, so it is opt-in."""
    if not opt.sixrd_prefix:
        return []
    try:
        n = ipaddress.ip_network(opt.sixrd_prefix, strict=False)
    except ValueError:
        return []
    if n.version != 6 or a not in n:
        return []
    # The IPv4 common prefix and its mask length are one unit: the mask says how
    # many high bits come from the ISP, the rest are carried in the IPv6 address.
    base_str = opt.sixrd_v4_prefix or "0.0.0.0/0"
    try:
        v4net = ipaddress.ip_network(base_str, strict=False)
    except ValueError:
        return []
    v4_masklen = opt.sixrd_v4_masklen if opt.sixrd_v4_masklen is not None else v4net.prefixlen

    bits = 32 - v4_masklen
    if not 0 < bits <= 32:
        return []
    if n.prefixlen + bits > 128:
        return []
    shift = 128 - n.prefixlen - bits
    suffix = (int(a) >> shift) & ((1 << bits) - 1)
    mask = ((1 << v4_masklen) - 1) << bits if v4_masklen else 0
    v4 = ipaddress.IPv4Address((int(v4net.network_address) & mask) | suffix)
    return [
        Finding(
            "6rd (RFC 5969)",
            "deterministic",
            str(v4),
            f"6rd prefix {n} contributes a /{v4_masklen} IPv4 common prefix "
            f"({v4net.network_address}); the {bits} bits at offset {n.prefixlen} "
            f"of {a} supply the rest -> {v4}",
            extra={"note": "correctness depends on the ISP parameters you supplied"},
        )
    ]


# --------------------------------------------------------------------------
# Strategy 7..8 — strong, DNS-based (network)
# --------------------------------------------------------------------------
class DNS:
    """Run-scoped resolver: one cache, no process-global state, thread-safe.

    Strategies run in parallel, so nothing here may touch
    socket.setdefaulttimeout() — that setting is process-wide and one thread
    resetting it would silently clobber another thread's timeout.
    """

    def __init__(self, timeout: float = 4.0, servers: list[str] | None = None,
                 trace: bool = False):
        self.timeout = timeout
        self.servers = servers or []
        self.trace = trace
        self.dnssec_ad: dict[str, bool] = {}
        self._cache: dict[tuple[str, str], list[str]] = {}
        self._lock = threading.Lock()
        self._stdlib_lock = threading.Lock()

    # -- plumbing ---------------------------------------------------------
    def _resolver(self):
        res = dns.resolver.Resolver()
        res.lifetime = self.timeout
        res.timeout = self.timeout
        if self.servers:
            res.nameservers = list(self.servers)
        # Ask the recursor to report its DNSSEC verdict. Without the AD bit in
        # the query the answer comes back with AD clear even for signed zones,
        # which would look identical to "not validated".
        res.flags = dns.flags.RD | dns.flags.AD
        return res

    def _log(self, msg: str) -> None:
        if self.trace:
            print(C.dim(f"  [dns] {msg}"), file=sys.stderr)

    def _query(self, name: str, rdtype: str) -> list[str]:
        key = (name.lower().rstrip("."), rdtype)
        with self._lock:
            if key in self._cache:
                self._log(f"{rdtype} {name} (cached)")
                return self._cache[key]

        out: list[str] = []
        if HAVE_DNSPYTHON:
            try:
                res = self._resolver()
                qname = (
                    dns.reversename.from_address(name)
                    if rdtype == "PTR"
                    else name
                )
                ans = res.resolve(qname, rdtype)
                out = [str(r).rstrip(".") for r in ans]
                # The AD bit tells us the recursor validated DNSSEC for this
                # answer. Only meaningful if the recursor itself is trusted.
                try:
                    ad = bool(ans.response.flags & dns.flags.AD)
                    with self._lock:
                        self.dnssec_ad[f"{rdtype} {name}"] = ad
                except Exception:
                    pass
            except Exception as exc:
                self._log(f"{rdtype} {name} failed: {type(exc).__name__}")
        else:
            # Stdlib fallback. getaddrinfo/gethostbyaddr have no per-call
            # timeout, so serialise them rather than race on a global one.
            with self._stdlib_lock:
                try:
                    if rdtype == "PTR":
                        host, aliases, _ = socket.gethostbyaddr(name)
                        out = [host] + list(aliases)
                    else:
                        fam = socket.AF_INET if rdtype == "A" else socket.AF_INET6
                        seen = []
                        for *_, sa in socket.getaddrinfo(name, None, fam):
                            if sa[0] not in seen:
                                seen.append(sa[0])
                        out = seen
                except Exception as exc:
                    self._log(f"{rdtype} {name} failed: {type(exc).__name__}")

        self._log(f"{rdtype} {name} -> {out or 'nothing'}")
        with self._lock:
            self._cache[key] = out
        return out

    # -- public API -------------------------------------------------------
    def ptr(self, ip: str) -> list[str]:
        return self._query(ip, "PTR")

    def a(self, host: str) -> list[str]:
        return self._query(host, "A")

    def aaaa(self, host: str) -> list[str]:
        return self._query(host, "AAAA")


def s_ptr_forward(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    """The workhorse for dual-stack hosts: PTR of the IPv6, then A of that name."""
    out: list[Finding] = []
    names = opt.dns.ptr(str(a))
    if not names:
        return []
    for name in names[: opt.max_names]:
        v4s = opt.dns.a(name)
        if not v4s:
            out.append(
                Finding(
                    "PTR (no A record)",
                    "informational",
                    None,
                    f"{a} -> PTR {name}, but {name} has no A record",
                )
            )
            continue
        for v4 in v4s:
            out.append(
                Finding(
                    "PTR -> A (dual-stack hostname)",
                    "strong",
                    v4,
                    f"{a} -> PTR {name} -> A {v4} — the same hostname answers on "
                    "both address families",
                    extra={"hostname": name},
                )
            )
    return out


# --------------------------------------------------------------------------
# Strategy 9 — strong, TLS certificate SANs (network, opt-in)
# --------------------------------------------------------------------------
_DNSNAME_RE = re.compile(rb"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,24}")


def _cert_sans(host_ip: str, port: int, timeout: float, sni: str | None = None) -> tuple[list[str], bool]:
    """Return (dns names, parsed_properly). Falls back to a DER scan if needed."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der: bytes | None = None
    try:
        with socket.create_connection((host_ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
    except Exception:
        return [], False
    if not der:
        return [], False
    if HAVE_CRYPTOGRAPHY:
        try:
            cert = x509.load_der_x509_certificate(der)
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return list(ext.value.get_values_for_type(x509.DNSName)), True
        except Exception:
            pass
    # Fallback: scrape plausible hostnames out of the DER blob.
    found = {m.decode() for m in _DNSNAME_RE.findall(der.lower())}
    return sorted(found), False


def s_tls_san(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    out: list[Finding] = []
    for port in opt.tls_ports:
        sans, parsed = _cert_sans(str(a), port, opt.timeout, opt.sni)
        if not sans:
            continue
        conf = "strong" if parsed else "weak"
        for name in sans[: opt.max_names]:
            if name.startswith("*."):
                name = name[2:]
            for v4 in opt.dns.a(name):
                out.append(
                    Finding(
                        f"TLS SAN -> A (port {port})",
                        conf,
                        v4,
                        f"certificate served by [{a}]:{port} lists {name}, "
                        f"which resolves to {v4}"
                        + ("" if parsed else " (SAN list recovered heuristically)")
                        + ("" if opt.sni else " [no SNI sent — this is the host's "
                           "default certificate and may belong to another tenant]"),
                        extra={"san": name, "port": port, "parsed": parsed},
                    )
                )
    return out


# --------------------------------------------------------------------------
# Strategy 10 — weak, RDAP same-organisation netblocks (network)
# --------------------------------------------------------------------------
def s_rdap(a: ipaddress.IPv6Address, opt) -> list[Finding]:
    if not HAVE_REQUESTS:
        return []
    try:
        r = requests.get(
            f"https://rdap.org/ip/{a}",
            timeout=opt.timeout,
            headers={"Accept": "application/rdap+json", "User-Agent": f"v4finder/{__version__}"},
        )
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []

    org = data.get("name") or ""
    handles = []
    for ent in data.get("entities", []) or []:
        h = ent.get("handle")
        if h:
            handles.append(h)
    out: list[Finding] = [
        Finding(
            "RDAP allocation",
            "informational",
            None,
            f"{a} belongs to {org or 'an unnamed allocation'} "
            f"({data.get('handle', '?')}, {data.get('country', '??')})",
            extra={"org": org, "handles": handles[:5]},
        )
    ]
    if not opt.rdap_netblocks:
        return out

    # ARIN exposes an entity's networks directly; that is the only RIR where
    # this is a single cheap call, so keep the scope tight and honest.
    seen: set[str] = set()
    for h in handles[:3]:
        try:
            er = requests.get(
                f"https://rdap.arin.net/registry/entity/{h}",
                timeout=opt.timeout,
                headers={"Accept": "application/rdap+json"},
            )
            if er.status_code != 200:
                continue
            for net in (er.json().get("networks") or [])[: opt.max_netblocks]:
                if net.get("ipVersion") != "v4":
                    continue
                start, end = net.get("startAddress"), net.get("endAddress")
                if not start or start in seen:
                    continue
                seen.add(start)
                out.append(
                    Finding(
                        "RDAP same-org IPv4 netblock",
                        "weak",
                        f"{start} - {end}",
                        f"entity {h} ({net.get('name', '?')}) also holds this IPv4 "
                        "range — the host is somewhere in this org's space, "
                        "this is NOT its address",
                        extra={"handle": h, "net_name": net.get("name")},
                    )
                )
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------
# Verification pass — forward-confirmation (FCrDNS)
# --------------------------------------------------------------------------
def verify(findings: list[Finding], a: ipaddress.IPv6Address, opt) -> None:
    """Decide how much a hostname-derived finding is actually worth.

    A PTR record is a unilateral claim by whoever controls the reverse zone.
    Anyone with a /64 can point its PTR at google.com; without checking the
    other direction we would happily report Google's IPv4 as "strong". So for
    every hostname-derived finding we ask the hostname itself:

      AAAA contains the target   -> forward-confirmed, promote to "confirmed"
      AAAA exists, target absent -> the PTR is stale or lying, demote to "weak"
      no AAAA at all             -> unconfirmable, leave at "strong" and say so

    We also do the cheaper IPv4-side check (does the candidate's own PTR name
    match?) purely as extra evidence; it never changes the tier on its own.
    """
    if opt.offline or not opt.verify:
        return

    for f in findings:
        if not f.ipv4 or "-" in f.ipv4 or f.confidence not in ("strong", "weak"):
            continue
        # The same three branches serve PTR-derived and certificate-derived
        # findings, so name whichever one actually made the claim — the
        # evidence must not cite a record type we never consulted.
        if f.extra.get("hostname"):
            host, claim = f.extra["hostname"], "PTR record"
        elif f.extra.get("san"):
            host, claim = f.extra["san"], "certificate SAN"
        else:
            continue

        # --- forward confirmation, the part that moves the tier ---
        norm = {_norm6(x) for x in opt.dns.aaaa(host)}
        if norm and _norm6(str(a)) in norm:
            f.confidence = "confirmed"
            f.extra["forward_confirmed"] = True
            f.evidence += (
                f"  [forward-confirmed: {host} AAAA includes {a}, so the "
                f"{claim} is corroborated by the forward zone]"
            )
        elif norm:
            f.confidence = "weak"
            f.extra["forward_confirmed"] = False
            f.extra["hostname_aaaa"] = sorted(norm)[:3]
            f.evidence += (
                f"  [NOT forward-confirmed: {host} has AAAA records, none of "
                f"which is {a} — the {claim} is stale or names an unrelated "
                "host, so this IPv4 is probably not the target's]"
            )
        else:
            f.extra["forward_confirmed"] = None
            f.evidence += (
                f"  [unconfirmable: {host} publishes no AAAA, so the {claim} "
                "cannot be checked against the forward zone]"
            )

        # --- supporting evidence only ---
        rev = opt.dns.ptr(f.ipv4)
        if any(host.lower() == n.lower() for n in rev):
            f.extra["reverse_confirmed"] = True
            f.evidence += f"  [{f.ipv4} PTR also -> {host}]"
        elif rev:
            f.extra["reverse_confirmed"] = False
            f.extra["reverse_names"] = rev[:3]


def _norm6(x: str) -> str:
    """Compare IPv6 addresses by value, not by spelling."""
    try:
        return str(ipaddress.IPv6Address(x.strip()))
    except ValueError:
        return x.strip().lower()


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
OFFLINE_STRATEGIES: list[tuple[str, Callable]] = [
    ("ipv4-mapped", s_ipv4_mapped),
    ("6to4", s_6to4),
    ("teredo", s_teredo),
    ("isatap", s_isatap),
    ("nat64", s_nat64),
    ("6rd", s_6rd),
]

ONLINE_STRATEGIES: list[tuple[str, Callable]] = [
    ("ptr", s_ptr_forward),
    ("rdap", s_rdap),
]


def analyse(a: ipaddress.IPv6Address, opt) -> tuple[list[Finding], list[Notice]]:
    findings: list[Finding] = []
    notices: list[Notice] = classify_scope(a)

    strategies = list(OFFLINE_STRATEGIES)
    if not opt.offline:
        strategies += ONLINE_STRATEGIES
        if opt.tls:
            strategies.append(("tls", s_tls_san))

    selected = [
        (n, fn)
        for n, fn in strategies
        if (not opt.only or n in opt.only) and n not in opt.skip
    ]

    def run(item: tuple[str, Callable]) -> tuple[str, list[Finding], str | None, float]:
        name, fn = item
        t0 = time.monotonic()
        try:
            return name, fn(a, opt), None, time.monotonic() - t0
        except Exception as exc:  # a broken strategy must not kill the run
            return name, [], f"{type(exc).__name__}: {exc}", time.monotonic() - t0

    # The network strategies are independent and latency-bound, so run them
    # concurrently. Results are collected in the fixed order of `selected`,
    # never in completion order — otherwise dedup would pick a different
    # "first" finding on every run.
    if opt.workers > 1 and len(selected) > 1:
        with ThreadPoolExecutor(max_workers=opt.workers) as pool:
            results = list(pool.map(run, selected))
    else:
        results = [run(item) for item in selected]

    for name, got, err, secs in results:
        if err:
            notices.append(Notice("warn", f"strategy {name!r} failed: {err}"))
        if opt.trace:
            print(
                C.dim(f"  [strategy] {name}: {len(got)} finding(s) in {secs*1000:.0f} ms"),
                file=sys.stderr,
            )
        findings.extend(got)

    verify(findings, a, opt)

    # The AD bit says the recursor validated DNSSEC for those answers. It is
    # only worth as much as your trust in the recursor and the path to it, so
    # report it as context rather than folding it into a confidence tier.
    # The resolver cache is shared across a --stdin batch, so its AD table
    # accumulates. Report only names this target's own findings rest on,
    # otherwise target #2 inherits target #1's DNSSEC status.
    mine = {str(a).lower()}
    for f in findings:
        for k in ("hostname", "san"):
            if f.extra.get(k):
                mine.add(str(f.extra[k]).lower().rstrip("."))
    validated = sorted(
        q for q, ad in opt.dns.dnssec_ad.items()
        if ad and q.split(" ", 1)[-1].lower().rstrip(".") in mine
    )
    if validated:
        notices.append(
            Notice("info", f"DNSSEC-validated (AD bit) by the recursor: "
                           f"{', '.join(validated[:4])}")
        )

    if opt.public_only:
        findings = [
            f
            for f in findings
            if f.ipv4 is None or "-" in f.ipv4 or _valid_public_v4(f.ipv4)
        ]

    # Sort BEFORE dedup so the survivor of each duplicate group is chosen by
    # tier rather than by whichever thread happened to finish first.
    findings.sort(key=lambda f: f.sort_key())

    # Several strategies can legitimately surface the same address (a wildcard
    # SAN and its bare form, two PTR names pointing at one host). Keep the
    # best, but fold the alternate evidence into it rather than losing it.
    deduped: dict[tuple[str, str], Finding] = {}
    for f in findings:
        k = f.dedup_key()
        if k in deduped:
            prev = deduped[k]
            alt = f.extra.get("san") or f.extra.get("hostname")
            if alt:
                prev.extra.setdefault("also_via", [])
                if alt not in prev.extra["also_via"]:
                    prev.extra["also_via"].append(alt)
            continue
        deduped[k] = f
    findings = list(deduped.values())

    findings.sort(key=lambda f: f.sort_key())
    return findings, notices


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def render_text(a: ipaddress.IPv6Address, findings: list[Finding], notices: list[Notice], opt) -> None:
    print(C.bold(f"Target : {a}"))
    print(C.dim(f"         compressed={a.compressed}  exploded={a.exploded}"))
    print()

    for n in notices:
        pre = {"error": C.red("[!!]"), "warn": C.yellow("[! ]"), "info": C.dim("[ i]")}[n.level]
        print(f"{pre} {n.text}")
    if notices:
        print()

    actionable = [f for f in findings if f.ipv4 and f.confidence in ACTIONABLE_TIERS]
    if not actionable:
        print(C.red("  No IPv4 address is derivable from this IPv6 address."))
        print(
            C.dim(
                "  It carries no transition-mechanism encoding, and no DNS or\n"
                "  certificate evidence ties it to an IPv4 host. For most\n"
                "  residential and mobile IPv6 addresses this is the correct\n"
                "  and expected answer — a native IPv6 address simply does not\n"
                "  contain an IPv4 address."
            )
        )
        info = [f for f in findings if f.confidence == "informational"]
        if info:
            print()
            print(C.dim("  Context gathered:"))
            for f in info:
                print(C.dim(f"    - {f.evidence}"))
        return

    current = None
    for f in findings:
        if f.confidence != current:
            current = f.confidence
            colour = CONF_COLOR.get(current, C.dim)
            print(colour(C.bold(f"  {current.upper()}")))
        tick = "  " if f.extra.get("reverse_confirmed") is not True else "*"
        val = f.ipv4 if f.ipv4 else C.dim("(no address)")
        flag = "" if f.routable else C.yellow("  [non-routable]")
        print(f"   {tick} {C.bold(str(val)):<28} {C.dim(f.method)}{flag}")
        print(f"      {C.dim(f.evidence)}")
        for k, v in f.extra.items():
            if k in ("hostname", "san", "reverse_confirmed"):
                continue
            print(C.dim(f"      {k}: {v}"))
    print()
    best = actionable[0]
    print(C.bold("Best answer: ") + C.green(str(best.ipv4)) + C.dim(f"  ({best.confidence}, via {best.method})"))
    if best.confidence == "weak":
        # Two different things land in "weak" and they need different warnings.
        if best.extra.get("forward_confirmed") is False:
            print(C.yellow("  Warning: weak confidence — this hostname's forward zone "
                           "does not list the target, so the claim is contradicted."))
        else:
            print(C.yellow("  Warning: weak confidence — this is org-level context, "
                           "not a host address."))


def json_result(a: ipaddress.IPv6Address, findings: list[Finding], notices: list[Notice]) -> dict:
    actionable = [f for f in findings if f.ipv4 and f.confidence in ACTIONABLE_TIERS]
    return {
        "tool": "v4finder",
        "version": __version__,
        "target": str(a),
        "target_exploded": a.exploded,
        "derivable": bool(actionable),
        "best": asdict(actionable[0]) if actionable else None,
        "findings": [asdict(f) for f in findings],
        "notices": [asdict(n) for n in notices],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="v4finder",
        description="V4Finder — find the public IPv4 behind a public IPv6 address.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  v4finder 2002:c000:0204::1              # 6to4, deterministic
  v4finder 2001:0:4136:e378:8000:63bf:3fff:fdd2   # Teredo
  v4finder 2606:4700:4700::1111 --tls     # DNS + certificate evidence
  v4finder 2a00:1450:4007:80f::200e --json
  cat v6.txt | v4finder --stdin --json
  v4finder 2001:db8:c000:200::1 --nat64-prefix 2001:db8::/32
""",
    )
    p.add_argument("address", nargs="?", help="the public IPv6 address to resolve")
    p.add_argument("--stdin", action="store_true", help="read addresses from stdin, one per line")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--offline", action="store_true", help="structural analysis only, no network")
    p.add_argument("--tls", action="store_true", help="connect to the target and read certificate SANs (touches the target)")
    p.add_argument("--tls-ports", default="443", help="comma-separated ports for --tls (default 443)")
    p.add_argument("--rdap-netblocks", action="store_true", help="also list same-org IPv4 netblocks (weak confidence)")
    p.add_argument("--no-verify", dest="verify", action="store_false", help="skip the reverse-DNS confirmation pass")
    p.add_argument("--public-only", action="store_true", help="hide results that are not globally routable IPv4")
    p.add_argument("--resolver", default="", help="comma-separated DNS servers to query, e.g. 1.1.1.1 (requires dnspython)")
    p.add_argument("--workers", type=int, default=8, help="parallel strategy workers (1 = sequential, default 8)")
    p.add_argument("--trace", action="store_true", help="print per-strategy timings and DNS queries to stderr")
    p.add_argument("--timeout", type=float, default=4.0, help="per-network-operation timeout in seconds (default 4)")
    p.add_argument("--max-names", type=int, default=8, help="max hostnames to follow per source (default 8)")
    p.add_argument("--max-netblocks", type=int, default=10, help="max RDAP netblocks to list (default 10)")
    p.add_argument("--only", default="", help="run only these strategies (comma-separated)")
    p.add_argument("--skip", default="", help="skip these strategies (comma-separated)")
    p.add_argument("--nat64-prefix", help="network-specific NAT64 prefix, e.g. 2001:db8::/32")
    p.add_argument("--6rd-prefix", dest="sixrd_prefix", help="6rd delegated prefix, e.g. 2a01:e00::/26")
    p.add_argument("--6rd-v4-prefix", dest="sixrd_v4_prefix", help="6rd IPv4 common prefix as CIDR, e.g. 192.0.2.0/24")
    p.add_argument("--6rd-v4-masklen", dest="sixrd_v4_masklen", type=int, default=None, help="6rd IPv4 mask length (overrides the length in --6rd-v4-prefix)")
    p.add_argument("--sni", help="hostname to send as SNI when using --tls")
    p.add_argument("--no-banner", action="store_true", help="suppress the ASCII banner")
    p.add_argument("--version", action="version", version=f"v4finder {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    opt = p.parse_args(argv)

    opt.only = {s.strip() for s in opt.only.split(",") if s.strip()}
    opt.skip = {s.strip() for s in opt.skip.split(",") if s.strip()}

    # A typo here would silently run zero strategies and then print the
    # authoritative "nothing derivable" verdict — a confident false negative.
    known = {n for n, _ in OFFLINE_STRATEGIES} | {n for n, _ in ONLINE_STRATEGIES} | {"tls"}
    for flag, names in (("--only", opt.only), ("--skip", opt.skip)):
        bad = names - known
        if bad:
            p.error(f"{flag}: unknown strategy {', '.join(sorted(bad))} "
                    f"(known: {', '.join(sorted(known))})")
    if "tls" in opt.only:
        opt.tls = True
    if opt.sixrd_v4_prefix and opt.sixrd_v4_masklen is None and "/" not in opt.sixrd_v4_prefix:
        p.error("--6rd-v4-prefix needs a mask length: give it as CIDR "
                "(192.0.2.0/24) or pass --6rd-v4-masklen")
    if opt.nat64_prefix:
        try:
            _n = ipaddress.ip_network(opt.nat64_prefix, strict=False)
            if _n.prefixlen not in _RFC6052_LENS:
                p.error(f"--nat64-prefix: RFC 6052 allows only /"
                        f"{', /'.join(str(x) for x in _RFC6052_LENS)}, got /{_n.prefixlen}")
        except ValueError as exc:
            p.error(f"--nat64-prefix: {exc}")
    try:
        opt.tls_ports = [int(x) for x in str(opt.tls_ports).split(",") if x.strip()]
    except ValueError:
        p.error("--tls-ports must be a comma-separated list of integers")
    if opt.workers < 1:
        p.error("--workers must be at least 1")

    servers = [x.strip() for x in opt.resolver.split(",") if x.strip()]
    for srv in servers:
        try:
            ipaddress.ip_address(srv)
        except ValueError:
            p.error(f"--resolver: {srv!r} is not an IP address")

    startup: list[Notice] = []
    if servers and not HAVE_DNSPYTHON:
        # Accepting a flag and then quietly ignoring it while still printing an
        # authoritative verdict is the failure mode this tool exists to avoid.
        startup.append(
            Notice(
                "warn",
                f"--resolver {','.join(servers)} IGNORED: dnspython is not "
                "installed, so the stdlib fallback must use /etc/resolv.conf. "
                "Install dnspython to choose a resolver.",
            )
        )
        servers = []

    opt.dns = DNS(timeout=opt.timeout, servers=servers, trace=opt.trace)

    show_banner = not opt.no_banner and not opt.json and sys.stdout.isatty()
    if show_banner:
        print(C.green(BANNER))
        print(C.dim(TAGLINE))
        print()

    if opt.stdin:
        targets = [ln.strip() for ln in sys.stdin if ln.strip() and not ln.startswith("#")]
    elif opt.address:
        targets = [opt.address]
    else:
        p.error("give an IPv6 address, or use --stdin")

    rc = 0
    results: list[dict] = []
    for i, raw in enumerate(targets):
        try:
            a = normalise_input(raw)
        except ValueError as exc:
            if opt.json:
                results.append({"target": raw, "error": str(exc), "derivable": False})
            else:
                print(C.red(f"[!!] {exc}"))
            rc = 2
            continue

        findings, notices = analyse(a, opt)
        notices = startup + notices
        if opt.json:
            results.append(json_result(a, findings, notices))
        else:
            if i:
                print(C.dim("-" * 68))
            render_text(a, findings, notices, opt)
            print()
        if not any(f.ipv4 and f.confidence in ACTIONABLE_TIERS for f in findings) and rc == 0:
            rc = 1

    if opt.json:
        # A single target prints one object; a batch prints one array, so the
        # output is always valid JSON in one parse.
        print(json.dumps(results[0] if len(results) == 1 else results, indent=2))
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
