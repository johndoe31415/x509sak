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
from x509sak.KwargsChecker import KwargsChecker
from x509sak.estimate import ExperimentalJudgementCodes

class JudgementCode(enum.Enum):
#	RSA_Parameter_Field_Not_Present = ("RSA pubkey", "parameter field not present")
#	RSA_Parameter_Field_Not_Null = ("RSA pubkey", "parameter field not NULL")
#	RSA_Exponent_Is_Zero_Or_Negative = ("RSA Exponent", "e is zero or negative")
#	RSA_Exponent_Is_0x1 = ("RSA Exponent", "e is 1")
#	RSA_Exponent_Small = ("RSA Exponent", "e is small")
#	RSA_Exponent_SmallUnusual = ("RSA Exponent", "e is small and uncommon")
#	RSA_Exponent_Is_0x10001 = ("RSA Exponent", "e is 0x10001")
#	RSA_Exponent_Large = ("RSA Exponent", "e is unusually large")
#	RSA_Modulus_Negative = ("RSA Modulus", "n is negative")
#	RSA_Modulus_Prime = ("RSA Modulus", "n is prime")
#	RSA_Modulus_Factorable = ("RSA Modulus", "n has small factors")
#	RSA_Modulus_FactorizationKnown = ("RSA Modulus", "factorization of n is public")
#	RSA_Modulus_BitBias = ("RSA Modulus", "n has bit bias")
#	RSA_Modulus_Length = ("RSA Modulus", "length of n")
#	RSA_PSS_Parameters_Malformed = ("RSA/PSS Encoding", "malformed parameters")
#	RSA_PSS_Parameters_TrailingData = ("RSA/PSS Encoding", "trailing garbage data")
#	RSA_PSS_Invalid_Salt_Length = ("RSA/PSS Salt", "length of salt invalid")
#	RSA_PSS_No_Salt_Used = ("RSA/PSS Salt", "no salt applied")
#	RSA_PSS_Short_Salt_Used = ("RSA/PSS Salt", "comparatively short salt value")
#	RSA_PSS_Salt_Length = ("RSA/PSS Salt", "length of salt")
#	RSA_PSS_Unknown_Trailer_Field = ("RSA/PSS Salt", "trailer field unknown")
#	RSA_PSS_Multiple_Hash_Functions = ("RSA/PSS Salt", "multiple hash functions used")
#	DSA_Parameter_P_BitBias = ("DSA parameters", "p has bit bias")
#	DSA_Parameter_Q_BitBias = ("DSA parameters", "q has bit bias")
#	DSA_Parameter_P_Not_Prime = ("DSA parameters", "p is not prime")
#	DSA_Parameter_Q_Not_Prime = ("DSA parameters", "q is not prime")
#	DSA_Parameter_Q_No_Divisor_Of_P1 = ("DSA parameters", "q does not divide (p - 1)")
#	DSA_Parameter_G_Invalid = ("DSA parameters", "generator g does not fulfill g^q = 1 mod p")
#	DSA_Parameter_G_Invalid_Range = ("DSA parameters", "generator g outside valid range")
#	DSA_Parameter_L_N_Uncommon = ("DSA parameters", "parameter values L/N are uncommon")
#	DSA_Parameter_L_N_Common = ("DSA parameters", "parameter values L/N are common")
#	DSA_Signature_R_BitBias = ("DSA signature", "R value has bit bias")
#	DSA_Signature_S_BitBias = ("DSA signature", "S value has bit bias")
#	DSA_Signature_Malformed = ("DSA signature", "signature is malformed")
#	DSA_Signature_TrailingData = ("DSA signature", "signature has trailing data")
	DSA_Security_Level = ("DSA parameters", "security estimation")
#	ECC_Pubkey_CurveOrder = ("ECC pubkey", "curve order")
#	ECC_Pubkey_Not_On_Curve = ("ECC pubkey", "point not on curve")
#	ECC_Pubkey_Is_G = ("ECC pubkey", "point is generator")
#	ECC_Pubkey_X_BitBias = ("ECC pubkey", "point's X coordinate has bit bias")
#	ECC_Pubkey_Y_BitBias = ("ECC pubkey", "point's Y coordinate has bit bias")
#	ECC_BinaryField = ("ECC domain", "binary finite field used for ECC")
#	ECC_BinaryFieldKoblitz = ("ECC domain", "Koblitz curve in binary field")
#	ECC_PrimeFieldKoblitz = ("ECC domain", "Koblitz curve in prime field")
#	ECC_ExplicitCurveEncoding = ("ECC domain", "explicit curve domain parameters")
#	ECC_UnknownNamedCurve = ("ECC domain", "curve with unknown name")
#	ECC_UnknownExplicitCurve = ("ECC domain", "curve with unknown parameters")
#	ECC_UnusedCurveName = ("ECC domain", "curve name that could be used")
#	ECC_DuplicatePolynomialPower = ("ECC domain", "duplicate power in field polynomial")
#	ECC_InvalidPolynomialPower = ("ECC domain", "invalid term in field polynomial")
#	ECDSA_Signature_R_BitBias = ("ECDSA signature", "R value has bit bias")
#	ECDSA_Signature_S_BitBias = ("ECDSA signature", "S value has bit bias")
#	ECDSA_Signature_TrailingData = ("ECDSA signature encoding", "trailing garbage data")
#	ECDSA_Signature_Malformed = ("ECDSA signature encoding", "invalid signature encoding")
#	Cert_Validity_NeverValid = ("Certificate validity", "certificate can never be valid")
#	Cert_Validity_NotYetValid = ("Certificate validity", "certificate not yet valid")
#	Cert_Validity_Expired = ("Certificate validity", "certificate expired")
#	Cert_Validity_Valid = ("Certificate validity", "certificate valid")
#	Cert_Validity_Length_Conservative = ("Certificate lifetime", "conservative lifetime")
#	Cert_Validity_Length_Long = ("Certificate validity", "long lifetime")
#	Cert_Validity_Length_VeryLong = ("Certificate validity", "very long lifetime")
#	Cert_Validity_Length_ExceptionallyLong = ("Certificate validity", "exceptionally long lifetime")
#	Cert_Validity_Invalid_NotBefore_Encoding = ("Certificate validity", "invalid 'Not Before' encoding")
#	Cert_Validity_Invalid_NotAfter_Encoding = ("Certificate validity", "invalid 'Not After' encoding")
#	Cert_Validity_GeneralizedTimeBeforeYear2050 = ("Certificate validity", "GeneralizedTime data type used for timestamp before year 2050")
#	Cert_X509Ext_Duplicate = ("X.509 extensions", "duplicate extensions present")
#	Cert_X509Ext_All_Unique = ("X.509 extensions", "all extensions unique")
#	Cert_X509Ext_EmptySequence = ("X.509 extensions", "extensions attribute is empty sequence")
	Cert_X509Ext_BasicConstraints_Missing = ("X.509 Basic Constraints extension", "BC extension missing")
	Cert_X509Ext_BasicConstraints_PresentButNotCritical = ("X.509 BasicConstraints extension", "BC extension present but not marked critical")
	Cert_X509Ext_BasicConstraints_PresentAndCritical = ("X.509 BasicConstraints extension", "BC extension present and marked critical")
	Cert_X509Ext_BasicConstraints_PathLenWithoutCA = ("X.509 BasicConstraints extension", "BC extension contains pathLen constraint without CA attribute")
	Cert_X509Ext_BasicConstraints_PathLenWithoutKeyCertSign = ("X.509 BasicConstraints extension", "BC extension contains pathLen constraint without keyCertSign KU")

	Cert_X509Ext_AuthorityKeyIdentifier_Malformed = ("X.509 AuthorityKeyIdentifier extension", "AKI extension malformed")
	Cert_X509Ext_AuthorityKeyIdentifier_Empty = ("X.509 AuthorityKeyIdentifier extension", "no key ID, CA name or serial given")
	Cert_X509Ext_AuthorityKeyIdentifier_Missing = ("X.509 AuthorityKeyIdentifier extension", "AKI extension missing")
	Cert_X509Ext_AuthorityKeyIdentifier_Critical = ("X.509 AuthorityKeyIdentifier extension", "AKI extension marked as critical")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_Empty = ("X.509 AuthorityKeyIdentifier CA name", "no names given")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_EmptyValue = ("X.509 AuthorityKeyIdentifier CA name", "no value given")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadIP = ("X.509 AuthorityKeyIdentifier CA name", "invalid IP address")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadIP_Private = ("X.509 AuthorityKeyIdentifier CA name", "IP address in unusual network space")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadEmail = ("X.509 AuthorityKeyIdentifier CA name", "invalid email address")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDNSName = ("X.509 AuthorityKeyIdentifier CA name", "invalid domain name")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDNSName_Space = ("X.509 AuthorityKeyIdentifier CA name", "domain name is just a space character")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadDNSName_SingleLabel = ("X.509 AuthorityKeyIdentifier CA name", "domain name consists only of single label")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_BadURI = ("X.509 AuthorityKeyIdentifier CA name", "invalid URI")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_UncommonURIScheme = ("X.509 AuthorityKeyIdentifier CA name", "uncommon URI scheme")
	Cert_X509Ext_AuthorityKeyIdentifier_CAName_UncommonIdentifier = ("X.509 AuthorityKeyIdentifier CA name", "uncommon name identifier")
	Cert_X509Ext_AuthorityKeyIdentifier_SerialWithoutName = ("X.509 AuthorityKeyIdentifier", "CA serial present, but not CA name")
	Cert_X509Ext_AuthorityKeyIdentifier_NameWithoutSerial = ("X.509 AuthorityKeyIdentifier", "CA name present, but no CA serial")
	Cert_X509Ext_AuthorityKeyIdentifier_NoKeyIDPresent = ("X.509 AuthorityKeyIdentifier", "no key ID present")
	Cert_X509Ext_AuthorityKeyIdentifier_KeyIDEmpty = ("X.509 AuthorityKeyIdentifier", "key ID present, but empty")
	Cert_X509Ext_AuthorityKeyIdentifier_KeyIDLong = ("X.509 AuthorityKeyIdentifier", "key ID very long")


	Cert_X509Ext_AuthorityKeyIdentifier_CA_NoSKI = ("X.509 AuthorityKeyIdentifier", "CA certificate does not contain SKI")
	Cert_X509Ext_AuthorityKeyIdentifier_CA_KeyIDMismatch = ("X.509 AuthorityKeyIdentifier", "key ID does not match CA SKI")
	Cert_X509Ext_AuthorityKeyIdentifier_CA_SerialMismatch = ("X.509 AuthorityKeyIdentifier", "serial does not match CA serial")

	Cert_X509Ext_SubjectKeyIdentifier_Missing = ("X.509 SubjectKeyIdentifier extension", "SKI extension missing")
	Cert_X509Ext_SubjectKeyIdentifier_Critical = ("X.509 SubjectKeyIdentifier extension", "SKI extension marked critical")
	Cert_X509Ext_SubjectKeyIdentifier_SHA1 = ("X.509 SubjectKeyIdentifier extension", "SKI matches SHA-1 hash of public key")
	Cert_X509Ext_SubjectKeyIdentifier_OtherHash = ("X.509 SubjectKeyIdentifier extension", "SKI matches a hash of public key, but not SHA-1")
	Cert_X509Ext_SubjectKeyIdentifier_Arbitrary = ("X.509 SubjectKeyIdentifier extension", "SKI does not appear to be hash of public key")

	Cert_X509Ext_NameConstraints_Empty = ("X.509 NameConstraints extension", "NameConstraints extension is empty")
	Cert_X509Ext_NameConstraints_PresentButNotCritical = ("X.509 NameConstraints extension", "NameConstraints extension not marked critical")
	Cert_X509Ext_NameConstraints_PresentButNotCA = ("X.509 NameConstraints extension", "NameConstraints extension in non-CA certificate")
	Cert_X509Ext_NameConstraints_Subtree_Name_BadIP = ("X.509 NameConstraints extension", "NameConstraints extension has invalid IP address")
	Cert_X509Ext_NameConstraints_Subtree_Name_RegisteredID = ("X.509 NameConstraints extension", "NameConstraints extension imposes restriction on RegisteredID")
	Cert_X509Ext_NameConstraints_Subtree_MinimumNotZero = ("X.509 NameConstraints extension", "NameConstraints subtreee has non-zero minium attribute")
	Cert_X509Ext_NameConstraints_Subtree_MaximumIsPresent = ("X.509 NameConstraints extension", "NameConstraints subtree has maximum attribute set")


	Cert_X509Ext_NotAllowed = ("X.509 extensions", "no extensions permissible")
	Cert_X509Ext_Malformed = ("X.509 extensions", "invalid extension encoding")

	Cert_X509Ext_KeyUsage_Missing = ("X.509 KeyUsage extension", "missing extension")
	Cert_X509Ext_KeyUsage_Empty = ("X.509 KeyUsage extension", "empty sequence")
	Cert_X509Ext_KeyUsage_TooLong = ("X.509 KeyUsage extension", "too many items")
	Cert_X509Ext_KeyUsage_Malformed = ("X.509 KeyUsage extension", "invalid extension encoding")
	Cert_X509Ext_KeyUsage_TrailingZeros = ("X.509 KeyUsage extension", "flag bitstring contains trailing zeros")
	Cert_X509Ext_KeyUsage_NonCritical = ("X.509 KeyUsage extension", "extension marked non-critical")
	Cert_X509Ext_KeyUsage_SignCertNoCA = ("X.509 KeyUsage extension", "keyCertSign flag present but not CA certificate")
	Cert_X509Ext_KeyUsage_SignCertNoBasicConstraints = ("X.509 KeyUsage extension", "keyCertSign flag present but no BasicConstraints extension")

	Cert_X509Ext_ExtKeyUsage_Empty = ("X.509 ExtendedKeyUsage extension", "empty sequence")
	Cert_X509Ext_ExtKeyUsage_Duplicate = ("X.509 ExtendedKeyUsage extension", "duplicate OIDs present")
	Cert_X509Ext_ExtKeyUsage_AnyUsageCritical = ("X.509 ExtendedKeyUsage extension", "AnyUsage present but extension marked as critical")

	Cert_X509Ext_Unknown_Critical = ("X.509 extensions", "unrecognized critical X.509 extension present")
	Cert_X509Ext_Unknown_NonCritical = ("X.509 extensions", "unrecognized X.509 extension present")

	Cert_X509Ext_IssuerAltName_Missing = ("X.509 IssuerAlternativeName", "extension missing although header issuer empty")
	Cert_X509Ext_IssuerAltName_Empty = ("X.509 IssuerAlternativeName", "no names given")
	Cert_X509Ext_IssuerAltName_EmptyValue = ("X.509 IssuerAlternativeName", "no value given")
	Cert_X509Ext_IssuerAltName_BadIP = ("X.509 IssuerAlternativeName", "invalid IP address")
	Cert_X509Ext_IssuerAltName_BadIP_Private = ("X.509 IssuerAlternativeName", "IP address in unusual network space")
	Cert_X509Ext_IssuerAltName_BadEmail = ("X.509 IssuerAlternativeName", "invalid email address")
	Cert_X509Ext_IssuerAltName_BadDNSName = ("X.509 IssuerAlternativeName", "invalid domain name")
	Cert_X509Ext_IssuerAltName_BadDNSName_Space = ("X.509 IssuerAlternativeName", "domain name is just a space character")
	Cert_X509Ext_IssuerAltName_BadDNSName_SingleLabel = ("X.509 IssuerAlternativeName", "domain name consists only of single label")
	Cert_X509Ext_IssuerAltName_BadURI = ("X.509 IssuerAlternativeName", "invalid URI")
	Cert_X509Ext_IssuerAltName_UncommonURIScheme = ("X.509 IssuerAlternativeName", "uncommon URI scheme")
	Cert_X509Ext_IssuerAltName_UncommonIdentifier = ("X.509 IssuerAlternativeName", "uncommon identifier")
	Cert_X509Ext_IssuerAltName_Critical = ("X.509 IssuerAlternativeName", "extension marked as critical")

	Cert_X509Ext_SubjectAltName_Missing = ("X.509 SubjectAlternativeName", "extension not present")
	Cert_X509Ext_SubjectAltName_Empty = ("X.509 SubjectAlternativeName", "no names given")
	Cert_X509Ext_SubjectAltName_EmptyValue = ("X.509 SubjectAlternativeName", "no value given")
	Cert_X509Ext_SubjectAltName_BadIP = ("X.509 SubjectAlternativeName", "invalid IP address")
	Cert_X509Ext_SubjectAltName_BadIP_Private = ("X.509 SubjectAlternativeName", "IP address in unusual network space")
	Cert_X509Ext_SubjectAltName_BadEmail = ("X.509 SubjectAlternativeName", "invalid email address")
	Cert_X509Ext_SubjectAltName_BadDNSName = ("X.509 SubjectAlternativeName", "invalid domain name")
	Cert_X509Ext_SubjectAltName_BadDNSName_Space = ("X.509 SubjectAlternativeName", "domain name is just a space character")
	Cert_X509Ext_SubjectAltName_BadDNSName_SingleLabel = ("X.509 SubjectAlternativeName", "domain name consists only of single label")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_NotLeftmost = ("X.509 SubjectAlternativeName", "wildcard appears not leftmost")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_MoreThanOneWildcard = ("X.509 SubjectAlternativeName", "more than one wildcard present")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_InternationalLabel = ("X.509 SubjectAlternativeName", "wildcard present in international label")
	Cert_X509Ext_SubjectAltName_BadWildcardDomain_BroadMatch = ("X.509 SubjectAlternativeName", "wildcard match too broad")
	Cert_X509Ext_SubjectAltName_BadURI = ("X.509 SubjectAlternativeName", "invalid URI")
	Cert_X509Ext_SubjectAltName_UncommonURIScheme = ("X.509 SubjectAlternativeName", "uncommon URI scheme")
	Cert_X509Ext_SubjectAltName_UncommonIdentifier = ("X.509 SubjectAlternativeName", "uncommon identifier")
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
	Cert_X509Ext_CertificatePolicies_UnknownQualifierOID = ("X.509 Certificate Policies extension", "unknown qualifier OID")
	Cert_X509Ext_CertificatePolicies_UserNoticeEmpty = ("X.509 Certificate Policies extension", "user notice contains no data")
	Cert_X509Ext_CertificatePolicies_UserNoticeConstraintViolation = ("X.509 Certificate Policies extension", "constraint violation in user notice")
	Cert_X509Ext_CertificatePolicies_UserNoticeRefPresent = ("X.509 Certificate Policies extension", "noticeRef field set in user notice")
	Cert_X509Ext_CertificatePolicies_UserNoticeMalformed = ("X.509 Certificate Policies extension", "error decoding user notice qualifier")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextInvalidStringType = ("X.509 Certificate Policies extension", "invalid explicitText string type")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextIA5String = ("X.509 Certificate Policies extension", "explicitText uses IA5String instead of UTF8String")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextControlCharacters = ("X.509 Certificate Policies extension", "control characters within explicitText")
	Cert_X509Ext_CertificatePolicies_UserNoticeExplicitTextAbsent = ("X.509 Certificate Policies extension", "explicitText field absent")
	Cert_X509Ext_CertificatePolicies_CPSMalformed = ("X.509 Certificate Policies extension", "error decoding CPS qualifier")
	Cert_X509Ext_CertificatePolicies_CPSConstraintViolation = ("X.509 Certificate Policies extension", "CPS qualifier uses illegal type")
	Cert_X509Ext_CertificatePolicies_CPSUnusualURIScheme = ("X.509 Certificate Policies extension", "CPS uses unusual URI scheme")

	Cert_X509Ext_NetscapeCertType_UnusedBitSet = ("Netscape Certificate Type extension", "unused type bit set")
	Cert_X509Ext_NetscapeCertType_Malformed = ("Netscape Certificate Type extension", "extension malformed")
	Cert_X509Ext_NetscapeCertType_Empty = ("Netscape Certificate Type extension", "no bits set")

	Cert_X509Ext_CRLDistributionPoints_Critical = ("CRL Distribution Points extension", "extension marked critical")
	Cert_X509Ext_CRLDistributionPoints_Malformed = ("CRL Distribution Points extension", "extension malformed")
	Cert_X509Ext_CRLDistributionPoints_NoPointWithAllReasonBits = ("CRL Distribution Points extension", "no distribution point with CRL for all reasons")
	Cert_X509Ext_CRLDistributionPoints_Point_Empty = ("CRL Distribution Points extension", "distribution point entirely empty")
	Cert_X509Ext_CRLDistributionPoints_Point_ContainsOnlyReasons = ("CRL Distribution Points extension", "distribution point contains only reasons field")
	Cert_X509Ext_CRLDistributionPoints_Point_NoLDAPOrHTTPURIPresent = ("CRL Distribution Points extension", "distribution point contains no LDAP or HTTP URI")
	Cert_X509Ext_CRLDistributionPoints_PointName_RDN_Malformed = ("CRL Distribution Points extension", "distribution point name uses malformed relative distinguished name")
	Cert_X509Ext_CRLDistributionPoints_PointName_RDN_Used = ("CRL Distribution Points extension", "distribution point name uses relative distinguished name")
	Cert_X509Ext_CRLDistributionPoints_PointName_RDN_Ambiguous = ("CRL Distribution Points extension", "distribution point name uses relative distinguished name even though multiple CRL issuer DNs present")
	Cert_X509Ext_CRLDistributionPoints_PointName_EmptyValue = ("CRL Distribution Points extension", "distribution point name contains empty value")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadEmail = ("CRL Distribution Points extension", "distribution point name contains invalid email")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadIP = ("CRL Distribution Points extension", "distribution point name contains invalid IP address")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadIP_Private = ("CRL Distribution Points extension", "distribution point name contains invalid IP address in unusual network space")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadURI = ("CRL Distribution Points extension", "distribution point name contains invalid URI")
	Cert_X509Ext_CRLDistributionPoints_PointName_UncommonURIScheme = ("CRL Distribution Points extension", "distribution point name contains uncommon URI scheme")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadDNSName = ("CRL Distribution Points extension", "distribution point name contains invalid domain name")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadDNSName_Space = ("CRL Distribution Points extension", "distribution point name contains domain name that is just space character")
	Cert_X509Ext_CRLDistributionPoints_PointName_BadDNSName_SingleLabel = ("CRL Distribution Points extension", "distribution point name contains domain name that consists only of single label")
	Cert_X509Ext_CRLDistributionPoints_PointName_UncommonIdentifier = ("CRL Distribution Points extension", "distribution point name contains uncommon identifier")
	Cert_X509Ext_CRLDistributionPoints_PointName_PossiblyNoDERCRLServed = ("CRL Distribution Points extension", "distribution point name possibly serves no DER data")
	Cert_X509Ext_CRLDistributionPoints_PointName_ContainsNoLDAPDN = ("CRL Distribution Points extension", "distribution point name contains no LDAP DN")
	Cert_X509Ext_CRLDistributionPoints_PointName_ContainsInvalidLDAPDN = ("CRL Distribution Points extension", "distribution point name contains invalid LDAP DN")
	Cert_X509Ext_CRLDistributionPoints_PointName_ContainsNoLDAPAttrdesc = ("CRL Distribution Points extension", "distribution point name contains no LDAP attrdesc")
	Cert_X509Ext_CRLDistributionPoints_PointName_ContainsNoLDAPHostname = ("CRL Distribution Points extension", "distribution point name contains no LDAP hostname")
	Cert_X509Ext_CRLDistributionPoints_Reasons_SegmentationUsed = ("CRL Distribution Points extension", "distribution point CRL seems to be segmented by reason")
	Cert_X509Ext_CRLDistributionPoints_Reasons_UnusedBitAsserted = ("CRL Distribution Points extension", "distribution point CRL reason has unused bit asserted")
	Cert_X509Ext_CRLDistributionPoints_Reasons_UndefinedBitAsserted = ("CRL Distribution Points extension", "distribution point CRL reason has undefined bit asserted")
	Cert_X509Ext_CRLDistributionPoints_Reasons_TrailingBits = ("CRL Distribution Points extension", "distribution point CRL reason has trailing bits")
	Cert_X509Ext_CRLDistributionPoints_CRLIssuer_RedundantlyPresent = ("CRL Distribution Points extension", "CRL issuer is identical to certificate issuer, but cRLIssuer field present")
	Cert_X509Ext_CRLDistributionPoints_CRLIssuer_Name_EmptyValue = ("CRL Distribution Points extension", "distribution point issuer contains empty value")
	Cert_X509Ext_CRLDistributionPoints_CRLIssuer_Name_BadEmail = ("CRL Distribution Points extension", "distribution point issuer contains invalid email")
	Cert_X509Ext_CRLDistributionPoints_CRLIssuer_Name_BadURI = ("CRL Distribution Points extension", "distribution point issuer contains invalid URI")
	Cert_X509Ext_CRLDistributionPoints_CRLIssuer_Name_UncommonURIScheme = ("CRL Distribution Points extension", "distribution point issuer contains uncommon URI scheme")
	Cert_X509Ext_CRLDistributionPoints_CRLIssuer_Name_UncommonIdentifier = ("CRL Distribution Points extension", "distribution point issuer contains uncommon identifier")

	Cert_X509Ext_CertificateTransparencyPoison_IsPrecertificate = ("Certificate Transparency Precertificate Poison extension", "not a certificate, but precertificate")
	Cert_X509Ext_CertificateTransparencyPoison_NotCritical = ("Certificate Transparency Precertificate Poison extension", "extension not marked as critical")
	Cert_X509Ext_CertificateTransparencyPoison_MalformedPayload = ("Certificate Transparency Precertificate Poison extension", "extnValue is malformed")
	Cert_X509Ext_CertificateTransparencyPoison_InvalidPayload = ("Certificate Transparency Precertificate Poison extension", "extnValue is not NULL")
	Cert_X509Ext_CertificateTransparencySCTs_TrailingData = ("Certificate Transparency Signed Certificate Timestamps extension", "trailing data present in extension payload")
	Cert_X509Ext_CertificateTransparencySCTs_ASN1Malformed = ("Certificate Transparency Signed Certificate Timestamps extension", "extension ASN.1 encoding malformed")
	Cert_X509Ext_CertificateTransparencySCTs_ContentMalformed = ("Certificate Transparency Signed Certificate Timestamps extension", "extension content encoding malformed")
	Cert_X509Ext_CertificateTransparencySCTs_SCT_UnknownVersion = ("Certificate Transparency Signed Certificate Timestamps extension", "unknown version")
	Cert_X509Ext_CertificateTransparencySCTs_SCT_ImplausibleTimestamp = ("Certificate Transparency Signed Certificate Timestamps extension", "implausible timestamp")
	Cert_X509Ext_CertificateTransparencySCTs_SCT_InvalidSignatureFunction = ("Certificate Transparency Signed Certificate Timestamps extension", "invalid signature function")
	Cert_X509Ext_CertificateTransparencySCTs_SCT_InvalidHashFunction = ("Certificate Transparency Signed Certificate Timestamps extension", "invalid hash function")

	SignatureFunction_UncommonPaddingScheme = ("Signature function", "uncommon padding scheme")
	SignatureFunction_UncommonCryptosystem = ("Signature function", "uncommon cryptosystem")
	SignatureFunction_Common = ("Signature function", "common signature function")
	SignatureFunction_NonPreferred_OID = ("Signature function", "not preferred OID used")
	HashFunction_Length = ("Hash function", "length of output")
	HashFunction_Derated = ("Hash function", "derating of security level")
	Cert_Invalid_DER = ("Certificate encoding", "invalid DER used")
	Cert_Pubkey_ReencodingCheckMissing = ("Certificate encoding", "re-encoding of key not implemented")
	Cert_Pubkey_Invalid_DER = ("Certificate encoding", "invalid DER used in public key")
	Cert_CN_Match = ("Certificate identity", "CN matches expected name")
	Cert_CN_Match_MultiValue_RDN = ("Certificate identity", "CN matches expected name, but is multivalue RDN")
	Cert_CN_NoMatch = ("Certificate identity", "CN does not match expected name")
	Cert_SAN_Match = ("Certificate identity", "SAN matches expected name")
	Cert_SAN_NoMatch = ("Certificate identity", "SAN does not match expected name")
	Cert_Name_Verification_Failed = ("Certificate identity", "name verification failed")
	Cert_Unexpectedly_CA_Cert = ("Certificate purpose", "certificate is CA cert, but should not be")
	Cert_Unexpectedly_No_CA_Cert = ("Certificate purpose", "certificate is no CA cert, but should be")
	Cert_Purpose_EKU_NoClientAuth = ("Certificate purpose", "EKU extension does not contain clientAuth flag")
	Cert_Purpose_EKU_NoServerAuth = ("Certificate purpose", "EKU extension does not contain serverAuth flag")
	Cert_Purpose_KU_MissingKeyUsage = ("Certificate purpose", "KU extension does not contain a necessary flag")
	Cert_Purpose_KU_ExcessKeyUsage = ("Certificate purpose", "KU extension contains a forbidden flag")
	Cert_Purpose_KU_UnusualKeyUsage = ("Certificate purpose", "KU extension contains an unusual flag")
	Cert_Purpose_NSCT_NoSSLClient = ("Certificate purpose", "NSCT extension does not contain sslClient flag")
	Cert_Purpose_NSCT_NoSSLServer = ("Certificate purpose", "NSCT extension does not contain sslServer flag")
	Cert_Purpose_NSCT_NoCA = ("Certificate purpose", "NSCT extension does not contain any CA flag")
	Cert_Purpose_NSCT_NonSSLCA = ("Certificate purpose", "NSCT extension is a CA, but not for use in SSL")

	Cert_Version_Not_2 = ("Certificate version", "not v2 certificate")
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
	DN_Contains_Long_RDN = ("Distinguished name", "length of RDN exceeds maximum")
	DN_Contains_Malformed_RDN = ("Distinguished name", "RDN is malformed")
	DN_Contains_Unusually_Many_RDNs = ("Distinguished name", "unusually many RDNs present")
	DN_Contains_DuplicateRDNs = ("Distinguished name", "duplicate RDNs present")
	DN_Contains_No_CN = ("Distinguished name", "no CN present")
	DN_Contains_Multiple_CN = ("Distinguished name", "multiple CN fields present")
	DN_Contains_Duplicate_Set = ("Distinguished name", "duplicate in set present")
	DN_Contains_Duplicate_OID_In_Multivalued_RDN = ("Distinguished name", "duplicate OID in multivalued RDN")
	Cert_Unknown_SignatureAlgorithm = ("Certificate signature", "unknown signature algorithm")
	Cert_Unknown_HashAlgorithm = ("Certificate signature", "unknown hash function")
	Cert_Unknown_MaskAlgorithm = ("Certificate signature", "unknown mask function")
	CA_Relationship_CACertificateInvalidAsCA = ("Certificate Authority relationship", "CA certificate invalid as a CA")
	CA_Relationship_SignatureVerificationFailure = ("Certificate Authority relationship", "signature cannot be verified with CA public key")
	CA_Relationship_SignatureVerificationSuccess = ("Certificate Authority relationship", "signature valid under CA public key")
	CA_Relationship_SubjectIssuerMismatch = ("Certificate Authority relationship", "issuer of certificate does not match CA subject")
	CA_Relationship_SubjectIssuerMatch = ("Certificate Authority relationship", "issuer of certificate maches CA subject")
	CA_Relationship_AKI_CANameMismatch = ("Certificate Authority relationship", "authority key identifier CAname does not match CA")
	CA_Relationship_AKI_CANameMatch = ("Certificate Authority relationship", "authority key identifier CAname matches CA")
	CA_Relationship_AKI_SerialMismatch = ("Certificate Authority relationship", "authority key identifier serial does not match CA")
	CA_Relationship_AKI_SerialMatch = ("Certificate Authority relationship", "authority key identifier serial matches CA")
	CA_Relationship_AKI_KeyIDMismatch = ("Certificate Authority relationship", "authority key identifier key ID does not match CA")
	CA_Relationship_AKI_KeyIDMatch = ("Certificate Authority relationship", "authority key identifier key ID matches CA")
	CA_Relationship_AKI_UncheckableNoCASKI = ("Certificate Authority relationship", "subject has AKI keyid, but CA certificate has no SKI")
	CA_Relationship_Validity_TimestampMalformed = ("Certificate Authority relationship", "certificate or CA certificate has malformed validity timestamp")
	CA_Relationship_Validity_NoOverlap = ("Certificate Authority relationship", "certificate and CA certificate lifetimes do not overlap")
	CA_Relationship_Validity_PartialOverlap = ("Certificate Authority relationship", "certificate and CA certificate lifetimes partially overlap")
	CA_Relationship_Validity_FullOverlap = ("Certificate Authority relationship", "certificate and CA certificate lifetimes fully overlap")
	Analysis_Not_Implemented = ("x509sak", "functionality not implemented")

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
		# TODO disable check until refactoring of ExperimentalJudgementCode is finished
		#assert((code is None) or isinstance(code, JudgementCode))

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
			# TODO refactor
			if isinstance(self.code.value, tuple):
				return self.code.value[0]
			else:
				return self.code.value.topic

	@property
	def short_text(self):
		if self.code is None:
			return None
		else:
			# TODO refactor
			if isinstance(self.code.value, tuple):
				return self.code.value[1]
			else:
				return self.code.value.short_text

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
			# TODO this is broken until refactoring complete
			#code = getattr(JudgementCode, judgement_data["code"])
			code = None
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

	def dump(self, indent = 0):
		indent_str = ("    " * indent)
		print("%s%s" % (indent_str, str(self)))

	def __str__(self):
		return "SecurityJudgement<%s / %s>" % (self.code, self.text)

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

	def dump(self, indent = 0):
		indent_str = ("    " * indent)
		print("%sSecurityJudgements" % (indent_str))
		for judgement in self._judgements:
			judgement.dump(indent + 1)

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
		raise NotImplementedError(self.__class__.__name__)

	@classmethod
	def register(cls, decoree):
		assert(decoree._STD_TYPE is not None)
		cls._REGISTERED[decoree._STD_TYPE] = decoree
		return decoree

@StandardReference.register
class RFCReference(StandardReference):
	_STD_TYPE = "RFC"

	def __init__(self, rfcno, sect, verb, text):
		assert(verb in [ "SHOULD", "MUST", "RECOMMEND", "MAY", "SHALL" ])
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
			"SHALL":		StandardDeviationType.VIOLATION,
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

@StandardReference.register
class LiteratureReference(StandardReference):
	_STD_TYPE = "literature"
	_Arguments = KwargsChecker(required_arguments = set([ "author", "title" ]), optional_arguments = set([ "type", "year", "month", "source", "quote", "doi", "sect" ]), check_functions = {
		"year":		lambda x: isinstance(x, int),
		"month":	lambda x: isinstance(x, int) and (1 <= x <= 12),
	})

	def __init__(self, **kwargs):
		StandardReference.__init__(self)
		self._Arguments.check(kwargs, "LiteratureReference")
		self._fields = kwargs
		self._fields["type"] = self._STD_TYPE

	@property
	def deviation_type(self):
		return None

	@classmethod
	def from_dict(cls, data):
		return cls(**data)

	def to_dict(self):
		return dict(self._fields)

	def __str__(self):
		text = " and ".join(self._fields["author"])
		if self._fields["year"] is not None:
			text += " (%d)" % (self._fields["year"])
		text += ". \"%s\"" % (self._fields["title"])
		return text
