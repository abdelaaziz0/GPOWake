"""Narrow Active Directory PKINIT backend.

The wire construction follows Dirk-jan Mollema's MIT-licensed PKINITtools
``gettgtpkinit.py`` implementation, adapted to avoid printing AS-REP key
material and to return only an owner-scoped ccache to GPOWake.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import secrets

from asn1crypto import algos, cms, core, keys, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from minikerberos.common.ccache import CCACHE
from minikerberos.common.target import KerberosTarget
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.protocol.asn1_structs import (
    AS_REQ,
    EncASRepPart,
    KDCOptions,
    KDC_REQ_BODY,
    PA_PAC_REQUEST,
    PADATA_TYPE,
    PrincipalName,
)
from minikerberos.protocol.constants import NAME_TYPE, PaDataType
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from minikerberos.protocol.rfc4556 import (
    AuthPack,
    KDCDHKeyInfo,
    PA_PK_AS_REP,
    PA_PK_AS_REQ,
    PKAuthenticator,
)


_UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
_DH_PARAMETERS = {
    "p": int(
        "00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67"
        "cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25"
        "f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f"
        "406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffff"
        "ffffffff",
        16,
    ),
    "g": 2,
}


def _certificate_upns(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return ()
    result: list[str] = []
    for name in names:
        if not isinstance(name, x509.OtherName) or name.type_id != _UPN_OID:
            continue
        try:
            value = core.UTF8String.load(name.value).native
        except (TypeError, ValueError):
            value = core.BMPString.load(name.value).native
        if isinstance(value, str):
            result.append(value)
    return tuple(result)


def _validate_identity(
    certificate: x509.Certificate, username: str, domain: str
) -> None:
    upns = _certificate_upns(certificate)
    if not upns:
        # SID-only/strong-mapping certificates are still checked by the KDC.
        return
    expected = f"{username.rstrip('$')}@{domain.rstrip('.')}".casefold()
    matching = [upn for upn in upns if upn.rstrip(".").casefold() == expected]
    if len(matching) != 1:
        raise ValueError(
            "PFX certificate must contain exactly one UPN matching "
            f"{username}@{domain}"
        )


class _DiffieHellman:
    """Small RFC 4556 DH primitive independent of minikerberos.pkinit.

    Importing that module eagerly imports oscrypto, which cannot detect several
    current OpenSSL 3 builds. GPOWake needs only these three integer operations,
    so keeping them local removes a fragile native-runtime dependency.
    """

    def __init__(self, parameters: dict[str, int]):
        self.p = parameters["p"]
        self.g = parameters["g"]
        self._private_key = int.from_bytes(os.urandom(32), "big")
        self.dh_nonce = os.urandom(32)

    def get_public_key(self) -> int:
        return pow(self.g, self._private_key, self.p)

    def exchange(self, peer_public_key: int) -> bytes:
        shared = pow(peer_public_key, self._private_key, self.p)
        return shared.to_bytes(max(1, (shared.bit_length() + 7) // 8), "big")


class _ActiveDirectoryPKINIT:
    def __init__(
        self,
        private_key: rsa.RSAPrivateKey,
        certificate: asn1_x509.Certificate,
        crypto_certificate: x509.Certificate,
        diffie: _DiffieHellman,
    ) -> None:
        self.private_key = private_key
        self.certificate = certificate
        self.crypto_certificate = crypto_certificate
        self.diffie = diffie

    @classmethod
    def from_pfx(
        cls, path: str, password: str, dh_parameters: dict[str, int]
    ) -> "_ActiveDirectoryPKINIT":
        with open(path, "rb") as stream:
            key, certificate, _extra = pkcs12.load_key_and_certificates(
                stream.read(), password.encode() if password else None
            )
        if key is None or certificate is None:
            raise ValueError("PFX does not contain both a certificate and private key")
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("PKINIT currently requires an RSA private key")
        return cls(
            key,
            asn1_x509.Certificate.load(
                certificate.public_bytes(serialization.Encoding.DER)
            ),
            certificate,
            _DiffieHellman(dh_parameters),
        )

    def build_asreq(self, domain: str, username: str) -> bytes:
        realm = domain.upper()
        now = datetime.datetime.now(datetime.timezone.utc)
        request_body = KDC_REQ_BODY(
            {
                "kdc-options": KDCOptions(
                    {"forwardable", "renewable", "renewable-ok"}
                ),
                "cname": PrincipalName(
                    {
                        "name-type": NAME_TYPE.PRINCIPAL.value,
                        "name-string": [username],
                    }
                ),
                "realm": realm,
                "sname": PrincipalName(
                    {
                        "name-type": NAME_TYPE.SRV_INST.value,
                        "name-string": ["krbtgt", realm],
                    }
                ),
                "till": (now + datetime.timedelta(days=1)).replace(microsecond=0),
                "rtime": (now + datetime.timedelta(days=1)).replace(microsecond=0),
                "nonce": secrets.randbits(31),
                "etype": [18, 17],
            }
        )
        authenticator = PKAuthenticator(
            {
                "cusec": now.microsecond,
                "ctime": now.replace(microsecond=0),
                "nonce": secrets.randbits(31),
                # SHA-1 is fixed by the AD PKINIT CMS profile/RFC 4556.
                "paChecksum": hashlib.sha1(request_body.dump()).digest(),  # nosec B324
            }
        )
        parameters = keys.DomainParameters(
            {"p": self.diffie.p, "g": self.diffie.g, "q": 0}
        )
        public_key = keys.PublicKeyInfo(
            {
                "algorithm": keys.PublicKeyAlgorithm(
                    {
                        "algorithm": "1.2.840.10046.2.1",
                        "parameters": parameters,
                    }
                ),
                "public_key": self.diffie.get_public_key(),
            }
        )
        auth_pack = AuthPack(
            {
                "pkAuthenticator": authenticator,
                "clientPublicValue": public_key,
                "clientDHNonce": self.diffie.dh_nonce,
            }
        )
        payload = PA_PK_AS_REQ(
            {"signedAuthPack": self._sign_authpack(auth_pack.dump())}
        )
        return AS_REQ(
            {
                "pvno": 5,
                "msg-type": 10,
                "padata": [
                    {
                        "padata-type": int(PADATA_TYPE("PA-PAC-REQUEST")),
                        "padata-value": PA_PAC_REQUEST(
                            {"include-pac": True}
                        ).dump(),
                    },
                    {
                        "padata-type": PaDataType.PK_AS_REQ.value,
                        "padata-value": payload.dump(),
                    },
                ],
                "req-body": request_body,
            }
        ).dump()

    def _sign_authpack(self, data: bytes) -> bytes:
        digest_algorithm = algos.DigestAlgorithm(
            {"algorithm": "1.3.14.3.2.26"}
        )
        signed_attributes = cms.CMSAttributes(
            [
                cms.CMSAttribute(
                    {"type": "content_type", "values": ["1.3.6.1.5.2.3.1"]}
                ),
                cms.CMSAttribute(
                    {
                        "type": "message_digest",
                        # SHA-1 is fixed by the AD PKINIT CMS profile/RFC 4556.
                        "values": [hashlib.sha1(data).digest()],  # nosec B324
                    }
                ),
            ]
        )
        signer = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.IssuerAndSerialNumber(
                    {
                        "issuer": self.certificate.issuer,
                        "serial_number": self.certificate.serial_number,
                    }
                ),
                "digest_algorithm": digest_algorithm,
                "signed_attrs": signed_attributes,
                "signature_algorithm": algos.SignedDigestAlgorithm(
                    {"algorithm": "1.2.840.113549.1.1.1"}
                ),
                "signature": self.private_key.sign(
                    signed_attributes.dump(),
                    padding.PKCS1v15(),
                    hashes.SHA1(),  # nosec B303 -- required by the AD PKINIT CMS profile
                ),
            }
        )
        signed_data = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [digest_algorithm],
                "encap_content_info": cms.EncapsulatedContentInfo(
                    {"content_type": "1.3.6.1.5.2.3.1", "content": data}
                ),
                "certificates": [self.certificate],
                "signer_infos": cms.SignerInfos([signer]),
            }
        )
        return cms.ContentInfo(
            {"content_type": "1.2.840.113549.1.7.2", "content": signed_data}
        ).dump()

    def decrypt_asrep(self, response: dict) -> dict:
        pk_as_rep = next(
            (
                PA_PK_AS_REP.load(item["padata-value"]).native
                for item in response["padata"]
                if item["padata-type"] == 17
            ),
            None,
        )
        if pk_as_rep is None:
            raise ValueError("PA_PK_AS_REP was not present in the KDC response")
        content = cms.ContentInfo.load(pk_as_rep["dhSignedData"]).native["content"]
        key_info = content["encap_content_info"]
        if key_info["content_type"] != "1.3.6.1.5.2.3.2":
            raise ValueError("unexpected PKINIT key-info content type")
        auth_data = KDCDHKeyInfo.load(key_info["content"]).native
        public_key = int.from_bytes(
            core.BitString(auth_data["subjectPublicKey"]).dump()[7:], "big"
        )
        shared_key = self.diffie.exchange(public_key)
        full_key = shared_key + self.diffie.dh_nonce + pk_as_rep["serverDHNonce"]
        enctype = response["enc-part"]["etype"]
        cipher = _enctype_table[enctype]
        if enctype == Enctype.AES256:
            key_size = 32
        elif enctype == Enctype.AES128:
            key_size = 16
        else:
            raise ValueError(f"unsupported PKINIT AS-REP enctype {enctype}")
        material = b""
        counter = 0
        while len(material) < key_size:
            # The PKINIT DH key derivation is specified in terms of SHA-1.
            material += hashlib.sha1(  # nosec B324
                bytes([counter]) + full_key
            ).digest()
            counter += 1
        key = Key(cipher.enctype, material[:key_size])
        clear = cipher.decrypt(key, 3, response["enc-part"]["cipher"])
        return EncASRepPart.load(clear).native


def request_pkinit_tgt(
    *,
    pfx_path: str,
    pfx_password: str,
    username: str,
    domain: str,
    dc_ip: str,
    output_path: str,
    timeout: float,
) -> None:
    backend = _ActiveDirectoryPKINIT.from_pfx(
        pfx_path, pfx_password, _DH_PARAMETERS
    )
    _validate_identity(backend.crypto_certificate, username, domain)
    request = backend.build_asreq(domain, username)
    target = KerberosTarget(dc_ip, timeout=max(1, int(timeout)))
    response = KerberosClientSocket(target).sendrecv(request)
    decrypted = backend.decrypt_asrep(response.native)
    cache = CCACHE()
    cache.add_tgt(response.native, decrypted)
    cache.to_file(output_path)
