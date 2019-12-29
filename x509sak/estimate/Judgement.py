#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2019 Johannes Bauer
#
#	This file is part of x509sak.
#
#	x509sak is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	x509sak is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with x509sak; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import enum
from x509sak.Tools import JSONTools
from x509sak.Exceptions import LazyDeveloperException

class JudgementCode(enum.Enum):
	RSA_Parameter_Field_Not_Present = ("RSA pubkey", "parameter field not present")
	RSA_Parameter_Field_Not_Null = ("RSA pubkey", "parameter field not NULL")
	RSA_Exponent_Is_Zero_Or_Negative = ("RSA Exponent", "e is zero or negative")
	RSA_Exponent_Is_0x1 = ("RSA Exponent", "e is 1")
	RSA_Exponent_Small = ("RSA Exponent", "e is small")
	RSA_Exponent_SmallUnusual = ("RSA Exponent", "e is small and uncommon")
	RSA_Exponent_Is_0x10001 = ("RSA Exponent", "e is 0x10001")
	RSA_Exponent_Large = ("RSA Exponent", "e is unusually large")
	RSA_Modulus_Negative = ("RSA Modulus", "n is negative")
	RSA_Modulus_Prime = ("RSA Modulus", "n is prime")
	RSA_Modulus_Factorable = ("RSA Modulus", "n has small factors")
	RSA_Modulus_FactorizationKnown = ("RSA Modulus", "factorization of n is public")
	RSA_Modulus_BitBias = ("RSA Modulus", "n has bit bias")
	RSA_Modulus_Length = ("RSA Modulus", "length of n")
	RSA_PSS_Salt_Length = ("RSA/PSS Salt", "length of salt")
	RSA_PSS_Parameters_TrailingData = ("RSA/PSS Encoding", "trailing garbage data")
	ECC_Pubkey_CurveOrder = ("ECC pubkey", "curve order")
	ECC_Pubkey_Not_On_Curve = ("ECC pubkey", "point not on curve")
	ECC_Pubkey_Is_G = ("ECC pubkey", "point is generator")
	ECC_Pubkey_X_BitBias = ("ECC pubkey", "point's X coordinate has bit bias")
	ECC_Pubkey_Y_BitBias = ("ECC pubkey", "point's Y coordinate has bit bias")
	ECC_BinaryField = ("ECC domain", "binary finite field used for ECC")
	ECC_BinaryFieldKoblitz = ("ECC domain", "Koblitz curve in binary field")
	ECC_PrimeFieldKoblitz = ("ECC domain", "Koblitz curve in prime field")
	ECC_ExplicitCurveEncoding = ("ECC domain", "explicit curve domain parameters")
	ECC_UnknownNamedCurve = ("ECC domain", "curve with unknown name")
	ECC_UnknownExplicitCurve = ("ECC domain", "curve with unknown parameters")
	ECC_UnusedCurveName = ("ECC domain", "curve name that could be used")
	ECC_DuplicatePolynomialPower = ("ECC domain", "duplicate power in field polynomial")
	ECC_InvalidPolynomialPower = ("ECC domain", "invalid term in field polynomial")
	ECDSA_Signature_R_BitBias = ("ECDSA signature", "R value has bit bias")
	ECDSA_Signature_S_BitBias = ("ECDSA signature", "S value has bit bias")
	ECDSA_Signature_TrailingData = ("ECDSA signature encoding", "trailing garbage data")
	ECDSA_Signature_Malformed = ("ECDSA signature encoding", "invalid signature encoding")
	Cert_Validity_NeverValid = ("Certificate validity", "certificate can never be valid")
	Cert_Validity_NotYetValid = ("Certificate validity", "certificate not yet valid")
	Cert_Validity_Expired = ("Certificate validity", "certificate expired")
	Cert_Validity_Valid = ("Certificate validity", "certificate valid")
	Cert_Validity_Length_Conservative = ("Certificate lifetime", "conservative lifetime")
	Cert_Validity_Length_Long = ("Certificate validity", "long lifetime")
	Cert_Validity_Length_VeryLong = ("Certificate validity", "very long lifetime")
	Cert_Validity_Length_ExceptionallyLong = ("Certificate validity", "exceptionally long lifetime")
	Cert_Validity_Invalid_NotBefore_Encoding = ("Certificate validity", "invalid 'Not Before' encoding")
	Cert_Validity_Invalid_NotAfter_Encoding = ("Certificate validity", "invalid 'Not After' encoding")
	Cert_Validity_GeneralizedTimeBeforeYear2050 = ("Certificate validity", "GeneralizedTime data type used for timestamp before year 2050")
	Cert_X509Ext_Duplicate = ("X.509 extensions", "duplicate extensions present")
	Cert_X509Ext_All_Unique = ("X.509 extensions", "all extensions unique")
	Cert_X509Ext_BasicConstraints_Missing = ("X.509 Basic Constraints extension", "BC extension missing")
	Cert_X509Ext_BasicConstraints_PresentButNotCritical = ("X.509 BasicConstraints extension", "BC extension present but not marked critical")
	Cert_X509Ext_BasicConstraints_PresentAndCritical = ("X.509 BasicConstraints extension", "BC extension present and marked critical")
	Cert_X509Ext_AuthorityKeyIdentifier_Missing = ("X.509 AuthorityKeyIdentifier extension", "AKI extension missing")
	Cert_X509Ext_AuthorityKeyIdentifier_Critical = ("X.509 AuthorityKeyIdentifier extension", "AKI extension marked as critical")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_Empty = ("X.509 AuthorityKeyIdentifier CA name", "no names given")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_EmptyValue = ("X.509 AuthorityKeyIdentifier CA name", "no value given")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadIP = ("X.509 AuthorityKeyIdentifier CA name", "invalid IP address")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadEmail = ("X.509 AuthorityKeyIdentifier CA name", "invalid email address")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDomain = ("X.509 AuthorityKeyIdentifier CA name", "invalid domain name")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadURI = ("X.509 AuthorityKeyIdentifier CA name", "invalid URI")
	Cert_X509Ext_AuthorityKeyIdentifier_SerialWithoutName = ("X.509 AuthorityKeyIdentifier", "CA serial present, but not CA name")
	Cert_X509Ext_AuthorityKeyIdentifier_NameWithoutSerial = ("X.509 AuthorityKeyIdentifier", "CA name present, but no CA serial")
	Cert_X509Ext_AuthorityKeyIdentifier_NoKeyIDPresent = ("X.509 AuthorityKeyIdentifier", "no key ID present")
	Cert_X509Ext_AuthorityKeyIdentifier_KeyIDEmpty = ("X.509 AuthorityKeyIdentifier", "key ID present, but empty")
	Cert_X509Ext_AuthorityKeyIdentifier_KeyIDLong = ("X.509 AuthorityKeyIdentifier", "key ID very long")
	Cert_X509Ext_AuthorityKeyIdentifier_CA_NoSKI = ("X.509 AuthorityKeyIdentifier", "CA certificate does not contain SKI")
	Cert_X509Ext_AuthorityKeyIdentifier_CA_KeyIDMismatch = ("X.509 AuthorityKeyIdentifier", "key ID does not match CA SKI")
	Cert_X509Ext_AuthorityKeyIdentifier_CA_SerialMismatch = ("X.509 AuthorityKeyIdentifier", "serial does not match CA serial")
	Cert_X509Ext_SubjectKeyIdentifier_Missing = ("X.509 SubjectKeyIdentifier extension", "SKI extension missing")
	Cert_X509Ext_SubjectKeyIdentifier_SHA1 = ("X.509 SubjectKeyIdentifier extension", "SKI matches SHA-1 hash of public key")
	Cert_X509Ext_SubjectKeyIdentifier_OtherHash = ("X.509 SubjectKeyIdentifier extension", "SKI matches a hash of public key, but not SHA-1")
	Cert_X509Ext_SubjectKeyIdentifier_Arbitrary = ("X.509 SubjectKeyIdentifier extension", "SKI does not appear to be hash of public key")
	Cert_X509Ext_NameConstraints_PresentButNotCritical = ("X.509 NameConstraints extension", "NameConstraints extension not marked critical")
	Cert_X509Ext_NameConstraints_PresentButNotCA = ("X.509 NameConstraints extension", "NameConstraints extension in non-CA certificate")
	Cert_X509Ext_NotAllowed = ("X.509 extensions", "no extensions permissible")
	Cert_X509Ext_Malformed = ("X.509 extensions", "invalid extension encoding")
	Cert_X509Ext_Invalid_DER = ("X.509 extensions", "invalid DER used in extension")
	Cert_X509Ext_KeyUsage_Missing = ("X.509 KeyUsage extension", "missing extension")
	Cert_X509Ext_KeyUsage_Empty = ("X.509 KeyUsage extension", "empty sequence")
	Cert_X509Ext_KeyUsage_TooLong = ("X.509 KeyUsage extension", "too many items")
	Cert_X509Ext_KeyUsage_Malformed = ("X.509 KeyUsage extension", "invalid extension encoding")
	Cert_X509Ext_KeyUsage_NonCritical = ("X.509 KeyUsage extension", "extension marked non-critical")
	Cert_X509Ext_KeyUsage_SignCertNoCA = ("X.509 KeyUsage extension", "keyCertSign flag present but not CA certificate")
	Cert_X509Ext_KeyUsage_SignCertNoBasicConstraints = ("X.509 KeyUsage extension", "keyCertSign flag present but no BasicConstraints extension")
	Cert_X509Ext_ExtKeyUsage_Empty = ("X.509 ExtendedKeyUsage extension", "empty sequence")
	Cert_X509Ext_ExtKeyUsage_Duplicate = ("X.509 ExtendedKeyUsage extension", "duplicate OIDs present")
	Cert_X509Ext_ExtKeyUsage_AnyUsageCritical = ("X.509 ExtendedKeyUsage extension", "AnyUsage present but extension marked as critical")
	Cert_X509Ext_Unknown_Critical = ("X.509 extensions", "unrecognized critical X.509 extension present")
	Cert_X509Ext_Unknown_NonCritical = ("X.509 extensions", "unrecognized X.509 extension present")
	Cert_X509Ext_IssuerAltName_Empty = ("X.509 IssuerAlternativeName", "no names given")
	Cert_X509Ext_IssuerAltName_EmptyValue = ("X.509 IssuerAlternativeName", "no value given")
	Cert_X509Ext_IssuerAltName_BadIP = ("X.509 IssuerAlternativeName", "invalid IP address")
	Cert_X509Ext_IssuerAltName_BadEmail = ("X.509 IssuerAlternativeName", "invalid email address")
	Cert_X509Ext_IssuerAltName_BadDomain = ("X.509 IssuerAlternativeName", "invalid domain name")
	Cert_X509Ext_IssuerAltName_BadURI = ("X.509 IssuerAlternativeName", "invalid URI")
	Cert_X509Ext_IssuerAltName_Missing = ("X.509 IssuerAlternativeName", "extension not present")
	Cert_X509Ext_IssuerAltName_Critical = ("X.509 IssuerAlternativeName", "extension marked as critical")
	Cert_X509Ext_SubjectAltName_Missing = ("X.509 SubjectAlternativeName", "extension not present")
	Cert_X509Ext_SubjectAltName_Empty = ("X.509 SubjectAlternativeName", "no names given")
	Cert_X509Ext_SubjectAltName_EmptyValue = ("X.509 SubjectAlternativeName", "no value given")
	Cert_X509Ext_SubjectAltName_BadIP = ("X.509 SubjectAlternativeName", "invalid IP address")
	Cert_X509Ext_SubjectAltName_BadEmail = ("X.509 SubjectAlternativeName", "invalid email address")
	Cert_X509Ext_SubjectAltName_BadDomain = ("X.509 SubjectAlternativeName", "invalid domain name")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost = ("X.509 SubjectAlternativeName", "wildcard appears not leftmost")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard = ("X.509 SubjectAlternativeName", "more than one wildcard present")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel = ("X.509 SubjectAlternativeName", "wildcard present in international label")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch = ("X.509 SubjectAlternativeName", "wildcard match too broad")
	Cert_X509Ext_SubjectAltName_BadURI = ("X.509 SubjectAlternativeName", "invalid URI")
	Cert_X509Ext_SubjectAltName_Critical = ("X.509 SubjectAlternativeName", "extension marked as critical")
	Cert_X509Ext_SubjectAltName_NotCritical = ("X.509 SubjectAlternativeName", "extension not marked as critical")
	Cert_X509Ext_SubjectAltName_EmailOnly = ("X.509 SubjectAlternativeName", "all names are email addresses")
	Cert_X509Ext_AuthorityInformationAccess_Critical = ("X.509 AuthorityInformationAccess", "extension marked as critical")
	Cert_X509Ext_AuthorityInformationAccess_Empty = ("X.509 AuthorityInformationAccess", "extension contains no data")
	Cert_X509Ext_CertificatePolicies_DeprecatedOID = ("X.509 Certificate Policies extension", "deprectated OID used")
	Cert_X509Ext_CertificatePolicies_DuplicateOID = ("X.509 Certificate Policies extension", "duplicate OID used")
	Cert_X509Ext_CertificatePolicies_MoreThanOnePolicy = ("X.509 Certificate Policies extension", "more than one policy present")
	Cert_X509Ext_CertificatePolicies_DuplicateQualifierOID = ("X.509 Certificate Policies extension", "duplicate qualifier OID present")
	Cert_X509Ext_CertificatePolicies_AnyPolicyUnknownQualifier = ("X.509 Certificate Policies extension", "unknown qualifier OID used in anyPolicy")
	Cert_X509Ext_CertificatePolicies_UserNoticeRefPresent = ("X.509 Certificate Policies extension", "noticeRef field set in user notice")
	Cert_X509Ext_CertificatePolicies_UserNoticeDecodeError = ("X.509 Certificate Policies extension", "error decoding user notice qualifier")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextInvalidStringType = ("X.509 Certificate Policies extension", "invalid explicitText string type")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextIA5String = ("X.509 Certificate Policies extension", "explicitText uses IA5String instead of UTF8String")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextControlCharacters = ("X.509 Certificate Policies extension", "control characters within explicitText")
	Cert_X509Ext_CertificatePolicies_CPSDecodeError = ("X.509 Certificate Policies extension", "error decoding CPS qualifier")
	Cert_X509Ext_CertificatePolicies_CPSUnusualSchema = ("X.509 Certificate Policies extension", "CPS URI uses unusual schema")
	SignatureFunction_UncommonPaddingScheme = ("Signature function", "uncommon padding scheme")
	SignatureFunction_UncommonCryptosystem = ("Signature function", "uncommon cryptosystem")
	SignatureFunction_Common = ("Signature function", "common signature function")
	SignatureFunction_NonPreferred_OID = ("Signature function", "not preferred OID used")
	HashFunction_Length = ("Hash function", "length of output")
	HashFunction_Derated = ("Hash function", "derating of security level")
	Cert_Invalid_DER = ("Certificate encoding", "invalid DER used")
	Cert_Pubkey_ReencodingCheckMissing = ("Certificate encoding", "re-encoding of key not implemented")
	Cert_Pubkey_Invalid_DER = ("Certificate encoding", "invalid DER used in public key")
	Cert_Has_No_CN = ("Certificate identity", "no CN present")
	Cert_CN_Match = ("Certificate identity", "CN matches expected name")
	Cert_CN_Match_MultiValue_RDN = ("Certificate identity", "CN matches expected name, but is multivalue RDN")
	Cert_CN_NoMatch = ("Certificate identity", "CN does not match expected name")
	Cert_SAN_Match = ("Certificate identity", "SAN matches expected name")
	Cert_SAN_NoMatch = ("Certificate identity", "SAN does not match expected name")
	Cert_No_SAN_Present = ("Certificate identity", "SAN extension not present")
	Cert_Name_Verification_Failed = ("Certificate identity", "name verification failed")
	Cert_Unexpectedly_CA_Cert = ("Certificate purpose", "certificate is CA cert, but should not be")
	Cert_Unexpectedly_No_CA_Cert = ("Certificate purpose", "certificate is no CA cert, but should be")
	Cert_EKU_NoClientAuth = ("Certificate purpose", "EKU extension does not contain clientAuth flag")
	Cert_EKU_NoServerAuth = ("Certificate purpose", "EKU extension does not contain serverAuth flag")
	Cert_KU_MissingKeyUsage = ("Certificate purpose", "KU extension does not contain a necessary flag")
	Cert_KU_ExcessKeyUsage = ("Certificate purpose", "KU extension contains a forbidden flag")
	Cert_KU_UnusualKeyUsage = ("Certificate purpose", "KU extension contains an unusual flag")
	Cert_NSCT_NoSSLClient = ("Certificate purpose", "NSCT extension does not contain sslClient flag")
	Cert_NSCT_NoSSLServer = ("Certificate purpose", "NSCT extension does not contain sslServer flag")
	Cert_NSCT_NoCA = ("Certificate purpose", "NSCT extension does not contain any CA flag")
	Cert_Version_Not_3 = ("Certificate version", "not v3 certificate")
	Cert_Serial_Zero = ("Certificate serial", "serial is zero")
	Cert_Serial_Negative = ("Certificate serial", "serial is negative")
	Cert_Serial_Large = ("Certificate serial", "serial is too large")
	Cert_Signature_Algorithm_Mismatch = ("Certificate signature", "signature algorithm mismatch")
	Cert_UniqueID_NotAllowed = ("Certificate unique ID", "subject/issuer unique ID not allowed in version 1 certificate")
	Cert_UniqueID_NotAllowedForCA = ("Certificate unique ID", "subject/issuer unique ID not allowed in CA certificate")
	DN_Contains_Illegal_Char = ("Digstinguished name", "illegal character present")
	DN_Contains_Deprecated_Type = ("Distinguished name", "deprecated type present")
	DN_Contains_NonPrintable = ("Distinguished name", "non-printable type present")
	DN_Contains_MultiValues = ("Distinguished name", "multi-valued RDN present")
	Cert_Unknown_SignatureAlgorithm = ("Certificate signature", "unknown signature algorithm")
	Cert_Unknown_HashAlgorithm = ("Certificate signature", "unknown hash function")

	@property
	def topic(self):
		return self.value[0]

	@property
	def short_text(self):
		return self.value[1]

class Verdict(enum.IntEnum):
	NO_SECURITY = 0
	BROKEN = 1
	WEAK = 2
	MEDIUM = 3
	HIGH = 4
	BEST_IN_CLASS = 5

class Commonness(enum.IntEnum):
	HIGHLY_UNUSUAL = 0
	UNUSUAL = 1
	FAIRLY_COMMON = 2
	COMMON = 3

class Compatibility(enum.IntEnum):
	STANDARDS_DEVIATION = 0
	LIMITED_SUPPORT = 1
	FULLY_COMPLIANT = 2

class StandardDeviationType(enum.IntEnum):
	RECOMMENDATION = 0
	VIOLATION = 1

class SecurityJudgement():
	def __init__(self, code, text, bits = None, verdict = None, commonness = None, compatibility = None, prefix_topic = False, standard = None, literature = None):
		assert((code is None) or isinstance(code, JudgementCode))
		assert((bits is None) or isinstance(bits, (int, float)))
		assert((verdict is None) or isinstance(verdict, Verdict))
		assert((commonness is None) or isinstance(commonness, Commonness))
		assert((compatibility is None) or isinstance(compatibility, Compatibility))
		self._code = code
		self._text = text
		self._bits = bits
		self._verdict = verdict
		self._commonness = commonness
		self._compatibility = compatibility
		self._prefix_topic = prefix_topic
		self._standard = standard
		self._literature = literature
		if self._bits == 0:
			if self._verdict is None:
				self._verdict = Verdict.NO_SECURITY
			if self._commonness is None:
				self._commonness = Commonness.HIGHLY_UNUSUAL

	@property
	def code(self):
		return self._code

	@property
	def topic(self):
		if self.code is None:
			return None
		else:
			return self.code.topic

	@property
	def short_text(self):
		if self.code is None:
			return None
		else:
			return self.code.short_text

	@property
	def text(self):
		return self._text

	@property
	def bits(self):
		return self._bits

	@property
	def verdict(self):
		return self._verdict

	@property
	def commonness(self):
		return self._commonness

	@property
	def compatibility(self):
		return self._compatibility

	@property
	def standard(self):
		return self._standard

	@property
	def literature(self):
		return self._literature

	@classmethod
	def from_dict(cls, judgement_data):
		if "code" in judgement_data:
			code = getattr(JudgementCode, judgement_data["code"])
		else:
			code = None
		text = judgement_data["text"]
		bits = judgement_data.get("bits")
		verdict = judgement_data.get("verdict")
		if verdict is not None:
			verdict = Verdict(verdict["value"])
		commonness = judgement_data.get("commonness")
		if commonness is not None:
			commonness = Commonness(commonness["value"])
		compatibility = judgement_data.get("compatibility")
		if compatibility is not None:
			compatibility = Compatibility(compatibility["value"])
		standard = judgement_data.get("standard")
		if standard is not None:
			standard = StandardReference.from_dict(standard)
		literature = judgement_data.get("literature")
		if literature is not None:
			literature = LiteratureReference.from_dict(literature)
		return cls(code = code, text = text, bits = bits, verdict = verdict, commonness = commonness, compatibility = compatibility, standard = standard, literature = literature)

	def to_dict(self):
		result = {
			"code":				self.code.name if (self.code is not None) else None,
			"topic":			self.topic,
			"short_text":		self.short_text,
			"text":				self.text,
			"bits":				self.bits,
			"verdict":			JSONTools.translate(self.verdict) if (self.verdict is not None) else None,
			"commonness":		JSONTools.translate(self.commonness) if (self.commonness is not None) else None,
			"compatibility":	JSONTools.translate(self.compatibility) if (self.compatibility is not None) else None,
			"standard":			self.standard.to_dict() if (self.standard is not None) else None,
			"literature":		self.literature.to_dict() if (self.literature is not None) else None,
		}
		return { key: value for (key, value) in result.items() if value is not None }

	def __str__(self):
		return "SecurityJudgement<%s>" % (self.text)

class SecurityJudgements():
	def __init__(self):
		self._judgements = [ ]

	@staticmethod
	def _minof(items):
		result = None
		for item in items:
			if result is None:
				result = item
			elif item is not None:
				result = min(result, item)
		return result

	@property
	def uniform_topic(self):
		return len(set(item.topic for item in self)) in [ 0, 1 ]

	@property
	def bits(self):
		return self._minof(item.bits for item in self)

	@property
	def verdict(self):
		return self._minof(item.verdict for item in self)

	@property
	def commonness(self):
		return self._minof(item.commonness for item in self)

	@property
	def compatibility(self):
		return self._minof(item.compatibility for item in self)

	def summary_judgement(self):
		return SecurityJudgement(code = None, text = "Summary", bits = self.bits, verdict = self.verdict, commonness = self.commonness, compatibility = self.compatibility)

	def __iadd__(self, judgement):
		if judgement is None:
			# Simply ignore it.
			pass
		elif isinstance(judgement, SecurityJudgement):
			self._judgements.append(judgement)
		elif isinstance(judgement, SecurityJudgements):
			self._judgements += judgement
		else:
			raise NotImplementedError(judgement)
		return self

	@classmethod
	def from_dict(cls, judgements_data):
		judgements = cls()
		for judgement_data in judgements_data["components"]:
			judgements += SecurityJudgement.from_dict(judgement_data)
		return judgements

	def to_dict(self):
		result = {
			"bits":				self.bits,
			"verdict":			self.verdict,
			"commonness":		self.commonness,
			"compatibility":	self.compatibility,
			"components":		[ judgement.to_dict() for judgement in self._judgements ],
		}
		return { key: value for (key, value) in result.items() if value is not None }

	def __len__(self):
		return len(self._judgements)

	def __iter__(self):
		return iter(self._judgements)

	def __getitem__(self, index):
		return self._judgements[index]

	def __str__(self):
		return "SecurityJudgements<%s>" % (", ".join(str(judgement) for judgement in self))

class StandardReference():
	_STD_TYPE = None
	_REGISTERED = { }

	@classmethod
	def from_dict(cls, data):
		if data["type"] not in cls._REGISTERED:
			raise LazyDeveloperException("Class not registered for standards type '%s'." % (data["type"]))
		return cls._REGISTERED[data["type"]].from_dict(data)

	@property
	def deviation_type(self):
		raise NotImplementedError()

	@classmethod
	def register(cls, decoree):
		cls._REGISTERED[decoree._STD_TYPE] = decoree
		return decoree

@StandardReference.register
class RFCReference(StandardReference):
	_STD_TYPE = "RFC"

	def __init__(self, rfcno, sect, verb, text):
		assert(verb in [ "SHOULD", "MUST", "RECOMMEND", "MAY" ])
		StandardReference.__init__(self)
		self._rfcno = rfcno
		self._sect = sect
		self._verb = verb
		self._text = text

	@property
	def deviation_type(self):
		return {
			"SHOULD":		StandardDeviationType.RECOMMENDATION,
			"RECOMMEND":	StandardDeviationType.RECOMMENDATION,
			"MAY":			StandardDeviationType.RECOMMENDATION,
			"MUST":			StandardDeviationType.VIOLATION,
		}[self.verb]

	@property
	def rfcno(self):
		return self._rfcno

	@property
	def sect(self):
		return self._sect

	@property
	def verb(self):
		return self._verb

	@property
	def text(self):
		return self._text

	@classmethod
	def from_dict(cls, data):
		return cls(rfcno = data["rfcno"], sect = data["sect"], verb = data["verb"], text = data["text"])

	def to_dict(self):
		return {
			"type":				self._STD_TYPE,
			"rfcno":			self.rfcno,
			"sect":				self.sect,
			"verb":				self.verb,
			"text":				self.text,
			"deviation_type":	self.deviation_type,
		}

	def __str__(self):
		if isinstance(self.sect, str):
			return "RFC%d Sect. %s" % (self.rfcno, self.sect)
		else:
			return "RFC%d Sects. %s" % (self.rfcno, " / ".join(self.sect))

class LiteratureReference():
	def __init__(self, author, title, year = None, month = None, source = None):
		assert((year is None) or isinstance(year, int))
		assert((month is None) or (isinstance(month, int) and (1 <= month <= 12)))
		if isinstance(author, str):
			author = [ author ]
		else:
			author = list(author)
		self._fields = {
			"author":		author,
			"title":		title,
			"year":			year,
			"month":		month,
			"source":		source,
		}

	@classmethod
	def from_dict(cls, data):
		return cls(author = data["author"], title = data["title"], year = data.get("year"), month = data.get("month"), source = data.get("source"))

	def to_dict(self):
		return self._fields

	def __str__(self):
		text = " and ".join(self._fields["author"])
		if self._fields["year"] is not None:
			text += " (%d)" % (self._fields["year"])
		text += ". \"%s\"" % (self._fields["title"])
		return text
