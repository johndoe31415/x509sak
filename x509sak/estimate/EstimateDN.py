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

import pyasn1.type.char
from x509sak.OID import OIDDB
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, Commonness, RFCReference

@BaseEstimator.register
class DistinguishedNameSecurityEstimator(BaseEstimator):
	_ALG_NAME = "dn"
	_VALID_ALPHABETS = {
		pyasn1.type.char.PrintableString:		set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"),
	}

	_LARGE_RDN_AMOUNT = 20		# Warn if more than this amount of RDNs are present

	"""
	ub-common-name-length INTEGER ::= 64
	ub-country-name-alpha-length INTEGER ::= 2
	ub-country-name-numeric-length INTEGER ::= 3
	ub-domain-defined-attribute-type-length INTEGER ::= 8
	ub-domain-defined-attribute-value-length INTEGER ::= 128
	ub-domain-name-length INTEGER ::= 16
	ub-e163-4-number-length INTEGER ::= 15
	ub-e163-4-sub-address-length INTEGER ::= 40
	ub-emailaddress-length INTEGER ::= 255
	ub-generation-qualifier-length INTEGER ::= 3
	ub-given-name-length INTEGER ::= 16
	ub-initials-length INTEGER ::= 5
	ub-numeric-user-id-length INTEGER ::= 32
	ub-organizational-unit-name-length INTEGER ::= 32
	ub-organization-name-length INTEGER ::= 64
	ub-pds-name-length INTEGER ::= 16
	ub-pds-parameter-length INTEGER ::= 30
	ub-postal-code-length INTEGER ::= 16
	ub-surname-length INTEGER ::= 40
	ub-terminal-id-length INTEGER ::= 24
	ub-unformatted-address-length INTEGER ::= 180
	ub-x121-address-length INTEGER ::= 16
	"""
	_MAX_LENGTH = {
		OIDDB.RDNTypes.inverse("CN"):			64,
		OIDDB.RDNTypes.inverse("C"):			64,
		OIDDB.RDNTypes.inverse("emailAddress"):	255,
		OIDDB.RDNTypes.inverse("GN"):			16,
		OIDDB.RDNTypes.inverse("initials"):		5,
		OIDDB.RDNTypes.inverse("UID"):			32,
		OIDDB.RDNTypes.inverse("OU"):			32,
		OIDDB.RDNTypes.inverse("O"):			64,
		OIDDB.RDNTypes.inverse("postalCode"):	16,
		OIDDB.RDNTypes.inverse("SN"):			40,
		OIDDB.RDNTypes.inverse("x121Address"):	16,
	}

	def _analyze_rdn_item(self, rdn_item):
		judgements = SecurityJudgements()
		asn1type = type(rdn_item.asn1)
		if asn1type in self._VALID_ALPHABETS:
			valid_chars = self._VALID_ALPHABETS[asn1type]
			illegal_chars = set(rdn_item.printable) - valid_chars
			if len(illegal_chars) > 0:
				judgements += SecurityJudgement(JudgementCode.DN_Contains_Illegal_Char, "Distinguished name contains character(s) \"%s\" which are invalid for a %s at element \"%s\"." % ("".join(sorted(illegal_chars)), asn1type.__name__, OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if isinstance(rdn_item.asn1, pyasn1.type.char.TeletexString):
			judgements += SecurityJudgement(JudgementCode.DN_Contains_Deprecated_Type, "Distinguished name contains deprecated TeletexString at element \"%s\"." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if not rdn_item.decodable:
			judgements += SecurityJudgement(JudgementCode.DN_Contains_Malformed_RDN, "Distinguished name contains undecodable RDN element \"%s\"." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			max_length = self._MAX_LENGTH.get(rdn_item.oid)
			if max_length is not None:
				if len(rdn_item.printable) > max_length:
					standard = RFCReference(rfcno = 5280, sect = "A.1", verb = "MUST", text = "specifications of Upper Bounds MUST be regarded as mandatory from Annex B of ITU-T X.411 Reference Definition of MTS Parameter Upper Bounds")
					judgements += SecurityJudgement(JudgementCode.DN_Contains_Long_RDN, "Distinguished name contains RDN element \"%s\" which is supposed to have a maximum length of %d characters, but actually has a length of %d characters." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid)), max_length, len(rdn_item.printable)), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		return judgements

	def analyze(self, dn):
		judgements = SecurityJudgements()
		for rdn in dn:
			for rdn_item in rdn:
				judgements += self._analyze_rdn_item(rdn_item)
		if dn.rdn_count > self._LARGE_RDN_AMOUNT:
			judgements += SecurityJudgement(JudgementCode.DN_Contains_Unusually_Many_RDNs, "Distinguished name contains an unusually high amount of RDNs (%d)." % (dn.rdn_count), commonness = Commonness.UNUSUAL)

		return {
			"rfc2253":		dn.rfc2253_str,
			"pretty":		dn.pretty_str,
			"security":		judgements,
		}
