#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2018-2020 Johannes Bauer
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
from x509sak.estimate import ExperimentalJudgementCodes, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, Commonness, RFCReference, LiteratureReference

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
		OIDDB.RDNTypes.inverse("C"):			2,
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
			illegal_chars = set(rdn_item.printable_value) - valid_chars
			if len(illegal_chars) > 0:
				judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_IllegalCharacter, "Distinguished name contains character(s) \"%s\" which are invalid for a %s at element \"%s\"." % ("".join(sorted(illegal_chars)), asn1type.__name__, OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if isinstance(rdn_item.asn1, pyasn1.type.char.TeletexString):
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_DeprecatedType, "Distinguished name contains deprecated TeletexString at element \"%s\"." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if not rdn_item.decodable:
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_RDN_Malformed, "Distinguished name contains undecodable RDN element \"%s\"." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			max_length = self._MAX_LENGTH.get(rdn_item.oid)
			if max_length is not None:
				if len(rdn_item.printable_value) > max_length:
					standard = RFCReference(rfcno = 5280, sect = "A.1", verb = "MUST", text = "specifications of Upper Bounds MUST be regarded as mandatory from Annex B of ITU-T X.411 Reference Definition of MTS Parameter Upper Bounds")
					judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_RDN_LengthExceeded, "Distinguished name contains RDN element \"%s\" which is supposed to have a maximum length of %d characters, but actually has a length of %d characters." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid)), max_length, len(rdn_item.printable_value)), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if not rdn_item.printable:
			# TODO standards reference?
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_NonPrintable, "Distinguished name contains RDN element item \"%s\" (ASN.1 type %s) which is not printable." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid)), rdn_item.asn1.__class__.__name__), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

		return judgements

	def _analyze_rdn(self, rdn):
		judgements = SecurityJudgements()
		if rdn.component_cnt > 1:
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_RDN_MultiValuedRDN, "Distinguished name contains a multivalue RDN: %s" % (rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)

		rdn_data = [ (rdn_item.oid, rdn_item.derdata) for rdn_item in rdn ]
		rdn_data_set = set(rdn_data)
		if len(rdn_data) != len(rdn_data_set):
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_RDN_DuplicateSet, "Relative distinguished name contains identical value more than once in SET: %s" % (rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)

		rdn_oids = [ rdn_item.oid for rdn_item in rdn ]
		rdn_oids_set = set(rdn_oids)
		if len(rdn_oids) != len(rdn_oids_set):
			standard = LiteratureReference(author = "ITU-T", title = "Recommendation X.501: Information technology - Open Systems Interconnection – The Directory: Models", sect = "9.3", month = 8, year = 2005, quote = "The set that forms an RDN contains exactly one AttributeTypeAndDistinguishedValue for each attribute which contains distinguished values in the entry; that is, a given attribute type cannot appear twice in the same RDN.")
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_TODOREMOVEMEDuplicateOIDInMultivaluedRDN, "Multivalued relative distinguished name contains same OID more than once in: %s" % (rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		for rdn_item in rdn:
			judgements += self._analyze_rdn_item(rdn_item)
		return judgements

	def analyze(self, dn):
		judgements = SecurityJudgements()

		all_cns = dn.get_all(OIDDB.RDNTypes.inverse("CN"))
		if len(all_cns) == 0:
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_NoCN, "Certificate does not have any common name (CN) set.", commonness = Commonness.HIGHLY_UNUSUAL)
		elif len(all_cns) > 1:
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_MultipleCN, "Certificate does have more than one common name (CN) set; in particular, %d CN fields were encountered." % (len(all_cns)), commonness = Commonness.UNUSUAL)

		seen_oid_keys = set()
		for rdn in dn:
			judgements += self._analyze_rdn(rdn)

			oidkey = rdn.oidkey
			if oidkey in seen_oid_keys:
				oidkey_str = " + ".join(OIDDB.RDNTypes.get(oid, str(oid)) for oid in oidkey)
				judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_DuplicateRDNs, "Distinguished name contains RDN element at least twice: %s (at element %s)" % (oidkey_str, rdn.pretty_str), commonness = Commonness.UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)
			else:
				seen_oid_keys.add(oidkey)

		if dn.rdn_count > self._LARGE_RDN_AMOUNT:
			judgements += SecurityJudgement(ExperimentalJudgementCodes.X509Cert_Body_FIXME_UnusuallyManyRDNs, "Distinguished name contains an unusually high amount of RDNs (%d)." % (dn.rdn_count), commonness = Commonness.UNUSUAL)

		return {
			"rfc2253":		dn.rfc2253_str,
			"pretty":		dn.pretty_str,
			"security":		judgements,
		}
