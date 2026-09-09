"""
geo_ip.py
Looks up country/city/lat/lon for an IP using a local MaxMind
GeoLite2-City database. Private/reserved IPs (RFC1918, loopback,
link-local, multicast/broadcast) are reported as "Unknown" rather
than queried, since they're never in the database.

The .mmdb file itself is NOT committed to this repo (see README) -
download your own free copy from MaxMind and point GEOIP_DB_PATH
at it, or drop it in the project root as GeoLite2-City.mmdb.
"""

import ipaddress
import os

import geoip2.database
import geoip2.errors

GEOIP_DB_PATH = os.environ.get(
    "GEOIP_DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "GeoLite2-City.mmdb"),
)

_UNKNOWN = {
    "country": "Unknown",
    "city": "Unknown",
    "lat": None,
    "lon": None,
}

_reader = None
_reader_load_attempted = False


def _get_reader():
    """Lazily open the mmdb reader once; return None if unavailable."""
    global _reader, _reader_load_attempted
    if _reader_load_attempted:
        return _reader

    _reader_load_attempted = True
    if os.path.exists(GEOIP_DB_PATH):
        try:
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception as exc:  # corrupt/unreadable db
            print(f" Could not open GeoIP database at {GEOIP_DB_PATH}: {exc}")
            _reader = None
    else:
        print(
            f" GeoIP database not found at {GEOIP_DB_PATH} - "
            "geo fields will be reported as 'Unknown'. See README for setup."
        )
    return _reader


def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # malformed input -> don't bother querying
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def lookup_ip(ip):
    """
    Return {"country", "city", "lat", "lon"} for a public IP, or the
    "Unknown"/None sentinel values for private IPs or lookup misses.
    """
    if _is_private(ip):
        return dict(_UNKNOWN)

    reader = _get_reader()
    if reader is None:
        return dict(_UNKNOWN)

    try:
        response = reader.city(ip)
        return {
            "country": response.country.name or "Unknown",
            "city": response.city.name or "Unknown",
            "lat": response.location.latitude,
            "lon": response.location.longitude,
        }
    except geoip2.errors.AddressNotFoundError:
        return dict(_UNKNOWN)
    except Exception as exc:  # unexpected geoip2/db error - fail soft
        print(f" GeoIP lookup failed for {ip}: {exc}")
        return dict(_UNKNOWN)
