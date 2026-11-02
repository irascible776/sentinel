"""
Sentinel v2.0 — Pillar IV: Deterministic SSRF & Cloud Metadata Validator
Protects against Server-Side Request Forgery, Cloud IMDS theft (AWS/GCP/Azure),
and internal network probing via agent fetch_url, http_get, or curl tools.
"""

import socket
import ipaddress
import urllib.parse
from typing import Tuple, Optional


class SSRFFilter:
    # High-value cloud metadata targets & wire servers
    CLOUD_METADATA_IPS = {
        "169.254.169.254",  # AWS / Azure / GCP IMDSv1 & IMDSv2
        "fd00:ec2::254",    # AWS IPv6 IMDS
        "100.100.100.200",  # Alibaba Cloud metadata
        "168.63.129.16",    # Azure Wire Server & VM agent
    }

    METADATA_HOSTNAMES = {
        "localhost",
        "instance-data",
        "metadata",
        "metadata.google.internal",
        "metadata.gcp.internal",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster.local",
    }

    @classmethod
    def _parse_ip_candidate(cls, host_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """
        Parses standard, integer/decimal, octal, hex, and mixed dotted representations.
        Catches:
          - 2852039166 -> 169.254.169.254
          - 0xA9FEA9FE -> 169.254.169.254
          - 0251.0376.0251.0376 -> 169.254.169.254
          - 0251.254.169.254 (mixed octal/dec) -> 169.254.169.254
          - 0xa9.0xfe.0xa9.0xfe (dotted hex) -> 169.254.169.254
        """
        cleaned = host_str.strip().strip("[]")
        if not cleaned:
            return None

        # 1. Standard ipaddress parsing (IPv4 / IPv6)
        try:
            return ipaddress.ip_address(cleaned)
        except ValueError:
            pass

        # 2. Integer / Decimal notation (e.g. 2852039166)
        if cleaned.isdigit():
            try:
                val = int(cleaned)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # 3. Single hex notation (e.g. 0xA9FEA9FE)
        if cleaned.lower().startswith("0x") and "." not in cleaned:
            try:
                val = int(cleaned, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # 4. Mixed dotted notation (octal, hex, decimal per byte)
        parts = cleaned.split(".")
        if len(parts) == 4:
            parsed_bytes = []
            for p in parts:
                p_str = p.strip()
                try:
                    if p_str.lower().startswith("0x"):
                        val = int(p_str, 16)
                    elif p_str.startswith("0") and len(p_str) > 1 and p_str.isdigit():
                        val = int(p_str, 8)
                    elif p_str.isdigit():
                        val = int(p_str, 10)
                    else:
                        break
                    if 0 <= val <= 255:
                        parsed_bytes.append(str(val))
                    else:
                        break
                except (ValueError, OverflowError):
                    break
            if len(parsed_bytes) == 4:
                try:
                    return ipaddress.IPv4Address(".".join(parsed_bytes))
                except ValueError:
                    pass

        return None

    @classmethod
    def inspect_target(cls, target: str) -> Tuple[bool, str, Optional[str]]:
        """
        Inspects a URL or target hostname/IP.
        Returns:
            is_blocked: bool
            reason: str
            resolved_ip: Optional[str]
        """
        if not target or not isinstance(target, str):
            return False, "Empty or invalid target", None

        target = target.strip()
        if not target:
            return False, "Empty target", None

        # Prepend scheme if raw host/URL passed
        if "://" not in target:
            url_to_parse = f"http://{target}"
        else:
            url_to_parse = target

        try:
            parsed = urllib.parse.urlsplit(url_to_parse)
            hostname = parsed.hostname
        except Exception as e:
            return True, f"Malformed URL: {str(e)}", None

        if not hostname:
            # Check if raw target itself is an IP candidate
            candidate_ip = cls._parse_ip_candidate(target)
            if candidate_ip:
                return cls._evaluate_ip(candidate_ip)
            return True, "Invalid URL: missing hostname", None

        norm_host = hostname.lower().strip()

        # Check known cloud metadata & local hostnames
        if norm_host in cls.METADATA_HOSTNAMES:
            return True, f"Blocked access to cloud metadata/local hostname: {norm_host}", None

        # Check direct IP evasions (hex, octal, decimal, mixed)
        direct_ip = cls._parse_ip_candidate(norm_host)
        if direct_ip:
            return cls._evaluate_ip(direct_ip)

        # Resolve hostname via DNS to prevent DNS Rebinding / local mapping
        try:
            addr_info = socket.getaddrinfo(norm_host, None)
            for _, _, _, _, sockaddr in addr_info:
                resolved_ip_str = sockaddr[0]
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                is_blocked, reason, ip_out = cls._evaluate_ip(resolved_ip)
                if is_blocked:
                    return True, f"DNS resolved to forbidden destination: {reason}", ip_out
        except socket.gaierror:
            # Unresolvable domains aren't necessarily malicious SSRF targets
            return False, "Hostname unresolvable in DNS", None
        except Exception as e:
            return True, f"DNS resolution error: {str(e)}", None

        return False, "Target destination is valid public address", None

    @classmethod
    def _evaluate_ip(cls, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str, str]:
        """Verifies if an IP is cloud metadata, private, loopback, or non-global."""
        ip_str = str(ip_obj)

        # Check explicit Cloud IMDS / Wire Server match
        if ip_str in cls.CLOUD_METADATA_IPS:
            return True, f"Direct access to Cloud IMDS ({ip_str}) blocked", ip_str

        # Unpack IPv6-mapped IPv4
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            mapped_ipv4 = ip_obj.ipv4_mapped
            if str(mapped_ipv4) in cls.CLOUD_METADATA_IPS:
                return True, f"IPv6-mapped Cloud IMDS ({mapped_ipv4}) blocked", str(mapped_ipv4)
            if not mapped_ipv4.is_global:
                return True, f"IPv6-mapped Non-Global IP ({mapped_ipv4}) blocked", str(mapped_ipv4)

        if not ip_obj.is_global:
            if ip_obj.is_loopback:
                return True, f"Loopback address ({ip_str}) blocked", ip_str
            if ip_obj.is_private:
                return True, f"Internal/Private RFC-1918 address ({ip_str}) blocked", ip_str
            if ip_obj.is_link_local:
                return True, f"Link-local subnet ({ip_str}) blocked", ip_str
            return True, f"Non-global restricted IP address ({ip_str}) blocked", ip_str

        return False, "Allowed public IP", ip_str
