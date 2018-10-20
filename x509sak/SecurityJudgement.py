#       x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#       Copyright (C) 2018-2018 Johannes Bauer
#
#       This file is part of x509sak.
#
#       x509sak is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; this program is ONLY licensed under
#       version 3 of the License, later versions are explicitly excluded.
#
#       x509sak is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with x509sak; if not, write to the Free Software
#       Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#       Johannes Bauer <JohannesBauer@gmx.de>

import enum

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
	RSA_Modulus_Known = ("RSA Modulus", "factorization of n is public")
	RSA_Modulus_BitBias = ("RSA Modulus", "n has bit bias")
	RSA_Modulus_Length = ("RSA Modulus", "length of n")
	RSA_PSS_Salt_Length = ("RSA/PSS Salt", "length of salt")
	ECC_Pubkey_CurveOrder = ("ECC pubkey", "curve order")
	ECC_Pubkey_Not_On_Curve = ("ECC pubkey", "point not on curve")
	ECC_Pubkey_Is_G = ("ECC pubkey", "point is generator")
	ECC_Pubkey_X_BitBias = ("ECC pubkey", "point's X coordinate has bit bias")
	ECC_Pubkey_Y_BitBias = ("ECC pubkey", "point's Y coordinate has bit bias")
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
	Cert_X509Ext_SubjectKeyIdentifier_Missing = ("X.509 SubjectKeyIdentifier extension", "SKI extension missing")
	Cert_X509Ext_SubjectKeyIdentifier_SHA1 = ("X.509 SubjectKeyIdentifier extension", "SKI matches SHA-1 hash of public key")
	Cert_X509Ext_SubjectKeyIdentifier_OtherHash = ("X.509 SubjectKeyIdentifier extension", "SKI matches a hash of public key, but not SHA-1")
	Cert_X509Ext_SubjectKeyIdentifier_Arbitrary = ("X.509 SubjectKeyIdentifier extension", "SKI does not appear to be hash of public key")
	Cert_X509Ext_NameConstraints_PresentButNotCritical = ("X.509 NameConstraints extension", "NameConstraints extension not marked critical")
	Cert_X509Ext_NameConstraints_PresentButNotCA = ("X.509 NameConstraints extension", "NameConstraints extension in non-CA certificate")
	Cert_X509Ext_NotAllowed = ("X.509 extensions", "no extensions permissible")
	Cert_X509Ext_KeyUsage_Empty = ("X.509 KeyUsage extension", "empty sequence")
	Cert_X509Ext_KeyUsage_TooLong = ("X.509 KeyUsage extension", "too many items")
	Cert_X509Ext_KeyUsage_NonCritical = ("X.509 KeyUsage extension", "extension marked non-critical")
	Cert_X509Ext_KeyUsage_SignCertNoCA = ("X.509 KeyUsage extension", "keyCertSign flag present but not CA certificate")
	Cert_X509Ext_KeyUsage_SignCertNoBasicConstraints = ("X.509 KeyUsage extension", "keyCertSign flag present but no BasicConstraints extension")
	SignatureFunction_UncommonPaddingScheme = ("Signature function", "uncommon padding scheme")
	SignatureFunction_UncommonCryptosystem = ("Signature function", "uncommon cryptosystem")
	SignatureFunction_Common = ("Signature function", "common signature function")
	HashFunction_Length = ("Hash function", "length of output")
	HashFunction_Derated = ("Hash function", "derating of security level")
	Cert_Invalid_DER = ("Certificate encoding", "invalid DER used")
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
	Cert_NSCT_NoSSLClient = ("Certificate purpose", "NSCT extension does not contain sslClient flag")
	Cert_NSCT_NoSSLServer = ("Certificate purpose", "NSCT extension does not contain sslServer flag")
	Cert_NSCT_NoCA = ("Certificate purpose", "NSCT extension does not contain any CA flag")
	Cert_Version_Not_3 = ("Certificate version", "not v3 certificate")
	Cert_Serial_Zero = ("Certificate serial", "serial is zero")
	Cert_Serial_Negative = ("Certificate serial", "serial is negative")
	Cert_UniqueID_NotAllowed = ("Certificate unique ID", "subject/issuer unique ID not allowed in non-v2 certificate")
	DN_Contains_Illegal_Char = ("Digstinguished name", "illegal character present")
	DN_Contains_Deprecated_Type = ("Distinguished name", "deprecated type present")
	DN_Contains_NonPrintable = ("Distinguished name", "non-printable type present")
	DN_Contains_MultiValues = ("Distinguished name", "multi-valued RDN present")

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
	STANDARDS_VIOLATION = 0
	STANDARDS_RECOMMENDATION = 1
	LIMITED_SUPPORT = 2
	FULLY_COMPLIANT = 3

class SecurityJudgement(object):
	def __init__(self, code, text, bits = None, verdict = None, commonness = None, compatibility = None, prefix_topic = False):
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
		if self._bits == 0:
			if self._verdict is None:
				self._verdict = Verdict.NO_SECURITY
			if self._commonness is None:
				self._commonness = Commonness.HIGHLY_UNUSUAL

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
		return cls(code = code, text = text, bits = bits, verdict = verdict, commonness = commonness, compatibility = compatibility)

	@property
	def component_cnt(self):
		return 1

	@property
	def code(self):
		return self._code

	@property
	def text(self):
		if self._prefix_topic:
			return "%s: %s" % (self.code.topic, self._text)
		else:
			return self._text

	@property
	def topic_text(self):
		return "%s: %s" % (self.code.topic, self._text)

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

	def to_dict(self):
		result = {
			"code":				self.code.name,
			"topic":			self.code.topic,
			"short_text":		self.code.short_text,
			"text":				self.text,
			"bits":				self.bits,
			"verdict":			self.verdict,
			"commonness":		self.commonness,
			"compatibility":	self.compatibility,
		}
		return { key: value for (key, value) in result.items() if value is not None }

class SecurityJudgements(object):
	def __init__(self):
		self._judgements = [ ]

	@property
	def component_cnt(self):
		return sum(judgement.component_cnt for judgement in self._judgements)

	@staticmethod
	def _minof(a, b):
		if (a is None) and (b is None):
			return None
		elif (a is not None) and (b is not None):
			# Take minimum
			return min(a, b)
		elif b is None:
			return a
		else:
			return b

	@property
	def text(self):
		return " / ".join(component.topic_text for component in self._judgements)

	@property
	def topic_text(self):
		return self.text

	@property
	def bits(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.bits)
		return result

	@property
	def verdict(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.verdict)
		return result

	@property
	def commonness(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.commonness)
		return result

	@property
	def compatibility(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.compatibility)
		return result

	def __iadd__(self, judgement):
		if judgement is None:
			# Just ignore it
			return self
		assert(isinstance(judgement, (SecurityJudgement, SecurityJudgements)))
		if judgement.component_cnt > 0:
			self._judgements.append(judgement)
		return self

	def _clone(self):
		clone = SecurityJudgements()
		for item in self._judgements:
			if isinstance(item, SecurityJudgement):
				clone += item
			else:
				clone += item._clone()
		return clone

	def __add__(self, judgement):
		clone = self._clone()
		clone += judgement
		return clone

	def to_dict(self):
		result = {
			"text":				self.text,
			"bits":				self.bits,
			"verdict":			self.verdict,
			"commonness":		self.commonness,
			"compatibility":	self.compatibility,
			"components":		self._judgements,
		}
		return { key: value for (key, value) in result.items() if value is not None }

	def __iter__(self):
		for item in self._judgements:
			if isinstance(item, SecurityJudgement):
				yield item
			else:
				yield from item
