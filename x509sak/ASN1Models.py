#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2018 Johannes Bauer
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

from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ, char
from pyasn1_modules import rfc2315, rfc3280

class ECPVer(univ.Integer):
	"""RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

	ECPVer ::= INTEGER {ecpVer1(1)}
	"""
	namedValues = namedval.NamedValues(
		("ecpVer1", 1),
	)

class FieldID(univ.Sequence):
	"""RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

	FieldID ::= SEQUENCE {
		fieldType   OBJECT IDENTIFIER,
		parameters  ANY DEFINED BY fieldType
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("fieldType", univ.ObjectIdentifier()),
		namedtype.NamedType("parameters", univ.Any()),
	)

class FieldElement(univ.OctetString):
	"""RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

	FieldElement ::= OCTET STRING
	"""
	pass

class ECPoint(univ.OctetString):
	"""RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

	ECPoint ::= OCTET STRING
	"""
	pass

class Curve(univ.Sequence):
	"""RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

	Curve ::= SEQUENCE {
		a         FieldElement,
		b         FieldElement,
		seed      BIT STRING OPTIONAL
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("a", FieldElement()),
		namedtype.NamedType("b", FieldElement()),
		namedtype.OptionalNamedType("seed", univ.BitString()),
	)

class SpecifiedECDomain(univ.Sequence):
	"""RFC 3279: Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

	ECParameters ::= SEQUENCE {
		version   ECPVer,          -- version is always 1
		fieldID   FieldID,         -- identifies the finite field over which the curve is defined
		curve     Curve,           -- coefficients a and b of the elliptic curve
		base      ECPoint,         -- specifies the base point P on the elliptic curve
		order     INTEGER,         -- the order n of the base point
		cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", ECPVer()),
		namedtype.NamedType("fieldID", FieldID()),
		namedtype.NamedType("curve", Curve()),
		namedtype.NamedType("base", ECPoint()),
		namedtype.NamedType("order", univ.Integer()),
		namedtype.OptionalNamedType("cofactor", univ.Integer()),
	)

class ECParameters(univ.Choice):
	"""RFC5480: Elliptic Curve Cryptography Subject Public Key Information

	ECParameters ::= CHOICE {
		namedCurve         OBJECT IDENTIFIER
		-- implicitCurve   NULL
		-- specifiedCurve  SpecifiedECDomain
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("namedCurve", univ.ObjectIdentifier()),
		namedtype.NamedType("implicitCurve", univ.Null()),
		namedtype.NamedType("specifiedCurve", SpecifiedECDomain()),
	)

class ECFieldParametersPrimeField(univ.Integer):
	"""X9.62-1998: Public Key Cryptography for the Financial Services Industry

	Prime-p ::= INTEGER        -- Finite field F(p), where p is an odd prime
	"""
	pass

class ECFieldParametersCharacteristicTwoField(univ.Sequence):
	"""X9.62-1998: Public Key Cryptography for the Financial Services Industry

	Characteristic-two ::= SEQUENCE {
		m INTEGER,			-- Field size 2^m
		basis CHARACTERISTIC-TWO.&id({BasisTypes}),
		parameters CHARACTERISTIC-TWO.&Type({BasisTypes}{@basis})
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("m", univ.Integer()),
		namedtype.NamedType("basis", univ.ObjectIdentifier()),
		namedtype.NamedType("parameters", univ.Any()),
	)

class ECFieldParametersCharacteristicTwoFieldTrinomial(univ.Integer):
	"""X9.62-1998: Public Key Cryptography for the Financial Services Industry

	x^m + x^k + 1

	Trinomial ::= INTEGER
	"""
	pass

class ECFieldParametersCharacteristicTwoFieldPentanomial(univ.Sequence):
	"""X9.62-1998: Public Key Cryptography for the Financial Services Industry

	x^m + x^k3 + x^k2 + x^k1 + 1

	Pentanomial ::= SEQUENCE {
		k1 INTEGER,
		k2 INTEGER,
		k3 INTEGER
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("k1", univ.Integer()),
		namedtype.NamedType("k2", univ.Integer()),
		namedtype.NamedType("k3", univ.Integer()),
	)

class ECPrivateKeyVersion(univ.Integer):
	namedValues = namedval.NamedValues(
		("ecPrivkeyVer1", 1),
	)

class ECPrivateKey(univ.Sequence):
	"""RFC5915: Elliptic Curve Private Key Structure

	ECPrivateKey ::= SEQUENCE {
		version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
		privateKey     OCTET STRING,
		parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
		publicKey  [1] BIT STRING OPTIONAL
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", ECPrivateKeyVersion()),
		namedtype.NamedType("privateKey", univ.OctetString()),
		namedtype.OptionalNamedType("parameters", ECParameters().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
		namedtype.OptionalNamedType("publicKey", univ.BitString().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
	)

class PFXVersion(univ.Integer):
	namedValues = namedval.NamedValues(
		("v3", 3),
	)

class MacData(univ.Sequence):
	"""RFC7292: PKCS #12: Personal Information Exchange Syntax v1.1

	MacData ::= SEQUENCE {
		mac        DigestInfo,
		macSalt    OCTET STRING,
		iterations INTEGER DEFAULT 1
		-- Note: The default is for historical reasons and its use is
		-- deprecated.
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("mac", rfc2315.DigestInfo()),
		namedtype.NamedType("macSalt", univ.OctetString()),
		namedtype.OptionalNamedType("iterations", univ.Integer()),
	)

class PFX(univ.Sequence):
	"""RFC7292: PKCS #12: Personal Information Exchange Syntax v1.1

	PFX ::= SEQUENCE {
		 version    INTEGER {v3(3)}(v3,...),
		 authSafe   ContentInfo,
		 macData    MacData OPTIONAL
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", PFXVersion()),
		namedtype.NamedType("authSafe", rfc2315.ContentInfo()),
		namedtype.OptionalNamedType("macData", MacData()),
	)

class DSASignature(univ.Sequence):
	"""RFC5912: New ASN.1 Modules for the Public Key Infrastructure Using X.509 (PKIX)

	DSA-Sig-Value ::= SEQUENCE {
		r  INTEGER,
		s  INTEGER
	}

	ECDSA-Sig-Value ::= SEQUENCE {
		r  INTEGER,
		s  INTEGER
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("r", univ.Integer()),
		namedtype.NamedType("s", univ.Integer()),
	)

class HashAlgorithm(rfc3280.AlgorithmIdentifier): pass
class MaskGenAlgorithm(rfc3280.AlgorithmIdentifier): pass
class TrailerField(univ.Integer): pass

class RSASSA_PSS_Params(univ.Sequence):
	"""RFC3447: Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography Specifications Version 2.1

	RSASSA-PSS-params ::= SEQUENCE {
		hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
		maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
		saltLength         [2] INTEGER          DEFAULT 20,
		trailerField       [3] TrailerField     DEFAULT trailerFieldBC
	}
	"""
	componentType = namedtype.NamedTypes(
		namedtype.DefaultedNamedType("hashAlgorithm", HashAlgorithm().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
		namedtype.DefaultedNamedType("maskGenAlgorithm", MaskGenAlgorithm().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
		namedtype.DefaultedNamedType("saltLength", univ.Integer().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
		namedtype.DefaultedNamedType("trailerField", TrailerField().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
	)

class NetscapeCertificateType(univ.BitString):
	namedValues = namedval.NamedValues(
		("client", 0),
		("server", 1),
		("email", 2),
		("objsign", 3),
		("reserved", 4),
		("sslCA", 5),
		("emailCA", 6),
		("objCA", 7),
	)

class RelaxedDisplayText(univ.Choice):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("ia5String", char.IA5String()),
		namedtype.NamedType("visibleString", char.VisibleString()),
		namedtype.NamedType("bmpString", char.BMPString()),
		namedtype.NamedType("utf8String", char.UTF8String()),
	)

class RelaxedNoticeReference(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("organization", RelaxedDisplayText()),
	    namedtype.NamedType("noticeNumbers", univ.SequenceOf(componentType = univ.Integer())),
	)

class RelaxedUserNotice(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.OptionalNamedType("noticeRef", RelaxedNoticeReference()),
		namedtype.OptionalNamedType("explicitText", RelaxedDisplayText()),
	)

class RelaxedCPSuri(RelaxedDisplayText): pass
