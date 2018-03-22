import enum
import collections
import pyasn1.codec.der.decoder
from pyasn1_modules import rfc2459, rfc2437
from x509sak.OID import OID, OIDDB
from x509sak.PEMDERObject import PEMDERObject
from x509sak.Tools import ASN1Tools, ECCTools

_KnownAlgorithmOIDs = {
	"1.2.840.113549.1.1.1":		"rsaEncryption",
	"1.2.840.10045.2.1":		"ecPublicKey",
}

class PublicKeyType(enum.Enum):
	RSA = "rsaEncryption"
	ECC = "ecPublicKey"

class PublicKey(PEMDERObject):
	_PEM_MARKER = "PUBLIC KEY"
	_ASN1_MODEL = rfc2459.SubjectPublicKeyInfo
	_ECPoint = collections.namedtuple("ECPoint", [ "curve", "x", "y" ])

	@property
	def keytype(self):
		return self._keytype

	@property
	def key(self):
		return self._key

	def _post_decode_hook(self):
		alg_oid = str(self.asn1["algorithm"]["algorithm"])
		if alg_oid not in _KnownAlgorithmOIDs:
			raise Exception("Unable to deterimne public algorithm for OID %s." % (alg_oid))
		alg_oid = _KnownAlgorithmOIDs[alg_oid]
		self._keytype = PublicKeyType(alg_oid)

		inner_key = ASN1Tools.bitstring2bytes(self.asn1["subjectPublicKey"])
		if self._keytype == PublicKeyType.RSA:
			(self._key, tail) = pyasn1.codec.der.decoder.decode(inner_key, asn1Spec = rfc2437.RSAPublicKey())
		elif self._keytype == PublicKeyType.ECC:
			(x, y) = ECCTools.decode_enc_pubkey(inner_key)
			(alg_oid, tail) = pyasn1.codec.der.decoder.decode(self.asn1["algorithm"]["parameters"])
			alg_oid = str(alg_oid)
			if alg_oid not in OIDDB.KnownCurveOIDs:
				raise Exception("Unable to determine curve name for curve OID %s." % (alg_oid))
			self._key = self._ECPoint(curve = OIDDB.KnownCurveOIDs[alg_oid], x = x, y = y)
		else:
			raise Exception(NotImplemented)
