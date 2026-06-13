"""
TLS certificate authority for HTTPS interception.

Generates a local CA cert and signs per-host certificates on demand.
Mirrors the approach used by claude-tap via the `cryptography` library.
"""

from __future__ import annotations

import datetime
import ipaddress
import pathlib
import ssl
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_UTC = datetime.timezone.utc
_NOW = lambda: datetime.datetime.now(_UTC)


_CERT_DIR = pathlib.Path.home() / ".selfhswarm" / "certs"


class CertAuthority:
    """
    Local self-signed Certificate Authority.

    On first use, generates a CA key + cert and stores them under
    ~/.selfhswarm/certs/. Subsequent calls sign per-host leaf certs
    using that CA.

    To make the browser/curl trust the CA, run:
        selfhswarm ca trust
    """

    def __init__(self, cert_dir: pathlib.Path = _CERT_DIR) -> None:
        self._dir = cert_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ca_key, self._ca_cert = self._load_or_generate_ca()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def server_context(self, hostname: str) -> ssl.SSLContext:
        """Return an SSLContext presenting a cert signed for *hostname*."""
        key, cert = self._leaf_cert(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Write key/cert to tmp files (SSLContext.load_cert_chain needs files)
        key_path = self._dir / f"{hostname}.key"
        cert_path = self._dir / f"{hostname}.crt"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + self._ca_cert.public_bytes(serialization.Encoding.PEM)
        )
        ctx.load_cert_chain(str(cert_path), str(key_path))
        return ctx

    @property
    def ca_cert_path(self) -> pathlib.Path:
        return self._dir / "ca.crt"

    # ------------------------------------------------------------------
    # CA generation
    # ------------------------------------------------------------------

    def _load_or_generate_ca(
        self,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key_path = self._dir / "ca.key"
        cert_path = self._dir / "ca.crt"

        if key_path.exists() and cert_path.exists():
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            return key, cert  # type: ignore[return-value]

        key = _gen_rsa_key()
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "selfhswarm Local CA")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW())
            .not_valid_after(_NOW() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return key, cert

    # ------------------------------------------------------------------
    # Per-host leaf certs
    # ------------------------------------------------------------------

    @lru_cache(maxsize=256)
    def _leaf_cert(
        self, hostname: str
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = _gen_rsa_key()

        san_entries: list[x509.GeneralName] = [x509.DNSName(hostname)]
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname)))
        except ValueError:
            pass

        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW())
            .not_valid_after(
                _NOW() + datetime.timedelta(days=365)
            )
            .add_extension(
                x509.SubjectAlternativeName(san_entries), critical=False
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        return key, cert


def _gen_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    from cryptography.hazmat.backends import default_backend

    return rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
