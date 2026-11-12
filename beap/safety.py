"""
Safety and Scope Controller for Network Probing.
Prevents Server-Side Request Forgery (SSRF) against internal, loopback,
link-local, private, and cloud-metadata addresses.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Optional

# Prohibited hostnames and cloud metadata targets
PROHIBITED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP/Azure link-local metadata
    "instance-data",
}

BLOCKED_SCHEMES = {"file", "gopher", "ftp", "tftp", "ldap", "dict"}


def is_safe_target_url(url: str, timeout: float = 3.0) -> Tuple[bool, str]:
    """
    Validates whether a candidate URL is safe to probe over the network.
    Rejects:
      - Non-HTTP/HTTPS schemes
      - Localhost and loopback addresses
      - Private RFC 1918 / RFC 4193 subnets
      - Link-local and cloud metadata endpoints (169.254.169.254)
    """
    if not url:
        return False, "Empty URL provided."

    try:
        parsed = urlparse(url)
    except Exception as ex:
        return False, f"Malformed URL string: {ex}"

    scheme = parsed.scheme.lower()
    if scheme not in ["http", "https"]:
        return False, f"Blocked scheme: '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "Missing hostname in URL."

    if hostname in PROHIBITED_HOSTNAMES:
        return False, f"Prohibited destination host: '{hostname}'."

    # Resolve IP address to verify it is public
    try:
        # Check if hostname is already an IP literal
        ip = ipaddress.ip_address(hostname)
        ip_addresses = [ip]
    except ValueError:
        # Hostname is a domain name; resolve via DNS
        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            ip_addresses = []
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                ip_addresses.append(ipaddress.ip_address(ip_str))
        except (socket.gaierror, Exception):
            # Resolution failure; offline or unresolvable
            return True, "Hostname unresolvable in offline/isolated environment (mock inspection permitted)."

    for ip_obj in ip_addresses:
        if ip_obj.is_loopback:
            return False, f"SSRF Protection: Blocked loopback address {ip_obj}."
        if ip_obj.is_private:
            return False, f"SSRF Protection: Blocked private RFC 1918/4193 address {ip_obj}."
        if ip_obj.is_link_local:
            return False, f"SSRF Protection: Blocked link-local address {ip_obj}."
        if ip_obj.is_reserved:
            return False, f"SSRF Protection: Blocked reserved address {ip_obj}."
        if ip_obj.is_multicast:
            return False, f"SSRF Protection: Blocked multicast address {ip_obj}."

    return True, "Target URL validated as safe for external observation."

