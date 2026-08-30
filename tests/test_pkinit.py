from __future__ import annotations

import datetime
import os

import pytest


pytest.importorskip("minikerberos")

from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from minikerberos.protocol.asn1_structs import AS_REQ

from gpowake.pkinit_backend import (
    _ActiveDirectoryPKINIT,
    _DH_PARAMETERS,
    _validate_identity,
)


def _test_pfx(path, password: str = "pin") -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "auditor")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.OtherName(
                        x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                        core.UTF8String("auditor@corp.local").dump(),
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"auditor",
            key,
            certificate,
            None,
            serialization.BestAvailableEncryption(password.encode()),
        )
    )
    os.chmod(path, 0o600)


def test_pkinit_pfx_builds_ad_as_req_and_validates_upn(tmp_path) -> None:
    pfx = tmp_path / "auditor.pfx"
    _test_pfx(pfx)
    backend = _ActiveDirectoryPKINIT.from_pfx(
        str(pfx), "pin", _DH_PARAMETERS
    )
    _validate_identity(backend.crypto_certificate, "auditor", "corp.local")
    with pytest.raises(ValueError, match="exactly one UPN"):
        _validate_identity(backend.crypto_certificate, "other", "corp.local")

    request = AS_REQ.load(backend.build_asreq("corp.local", "auditor")).native
    assert request["req-body"]["realm"] == "CORP.LOCAL"
    assert request["req-body"]["cname"]["name-string"] == ["auditor"]
    assert request["req-body"]["sname"]["name-string"] == [
        "krbtgt",
        "CORP.LOCAL",
    ]
    assert {item["padata-type"] for item in request["padata"]} == {16, 128}
