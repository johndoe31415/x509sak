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

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful
from pyasn1_modules import rfc2315

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
