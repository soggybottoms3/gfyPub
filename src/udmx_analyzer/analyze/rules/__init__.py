"""Importing this package registers every built-in rule.

Each submodule defines one or more :class:`Rule` subclasses decorated with
``@register``. Importing them here is what populates the registry the engine
iterates over.
"""

from . import wan, wifi, system, security, dns_dhcp, firmware, config_rules  # noqa: F401

__all__ = [
    "wan",
    "wifi",
    "system",
    "security",
    "dns_dhcp",
    "firmware",
    "config_rules",
]
