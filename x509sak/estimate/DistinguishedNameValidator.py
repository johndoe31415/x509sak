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
from x509sak.estimate import Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, Commonness, RFCReference, LiteratureReference
from x509sak.estimate.Validator import BaseValidationResult, BaseValidator

class DistinguishedNameValidationResult(BaseValidationResult):
	_VALID_ALPHABETS = {
		pyasn1.type.char.PrintableString:		set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"),
	}
	_LARGE_RDN_AMOUNT = 20		# Warn if more than this amount of RDNs are present
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

	def _validate_rdn_component(self, rdn_item):
		asn1type = type(rdn_item.asn1)
		if asn1type in self._VALID_ALPHABETS:
			valid_chars = self._VALID_ALPHABETS[asn1type]
			illegal_chars = set(rdn_item.printable_value) - valid_chars
			if len(illegal_chars) > 0:
				self._report("Enc_DER_Struct_DN_IllegalCharacter", "distinguished name contains character(s) \"%s\" which are invalid for a %s at element \"%s\"." % ("".join(sorted(illegal_chars)), asn1type.__name__, OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if isinstance(rdn_item.asn1, pyasn1.type.char.TeletexString):
			self._report("Enc_DER_Struct_DN_DeprecatedType", "distinguished name contains deprecated TeletexString at element \"%s\"." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if not rdn_item.decodable:
			self._report("Enc_DER_Struct_DN_RDN_Malformed", "distinguished name contains undecodable RDN element \"%s\"." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			max_length = self._MAX_LENGTH.get(rdn_item.oid)
			if max_length is not None:
				if len(rdn_item.printable_value) > max_length:
					standard = RFCReference(rfcno = 5280, sect = "A.1", verb = "MUST", text = "specifications of Upper Bounds MUST be regarded as mandatory from Annex B of ITU-T X.411 Reference Definition of MTS Parameter Upper Bounds")
					self._report("Enc_DER_Struct_DN_RDN_LengthExceeded", "distinguished name contains RDN element \"%s\" which is supposed to have a maximum length of %d characters, but actually has a length of %d characters." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid)), max_length, len(rdn_item.printable_value)), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		if not rdn_item.printable:
			# TODO standards reference?
			self._report("Enc_DER_Struct_DN_NonPrintable", "distinguished name contains RDN element item \"%s\" (ASN.1 type %s) which is not printable." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid)), rdn_item.asn1.__class__.__name__), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

	def _validate_rdn(self, rdn):
		if rdn.component_cnt > 1:
			self._report("Enc_DER_Struct_DN_RDN_MultiValuedRDN", "distinguished name contains a multivalue RDN: %s" % (rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)

		rdn_data = [ (rdn_item.oid, rdn_item.derdata) for rdn_item in rdn ]
		rdn_data_set = set(rdn_data)
		if len(rdn_data) != len(rdn_data_set):
			self._report("Enc_DER_Struct_DN_RDN_DuplicateSet_Key_Value", "relative distinguished name contains identical key/value more than once in SET: %s" % (rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)

		rdn_oids = [ rdn_item.oid for rdn_item in rdn ]
		rdn_oids_set = set(rdn_oids)
		if len(rdn_oids) != len(rdn_oids_set):
			standard = LiteratureReference(author = "ITU-T", title = "Recommendation X.501: Information technology - Open Systems Interconnection – The Directory: Models", sect = "9.3", month = 8, year = 2005, quote = "The set that forms an RDN contains exactly one AttributeTypeAndDistinguishedValue for each attribute which contains distinguished values in the entry; that is, a given attribute type cannot appear twice in the same RDN.")
			self._report("Enc_DER_Struct_DN_RDN_DuplicateSet_Key", "multivalued relative distinguished name contains same key OID more than once in: %s" % (rdn.pretty_str), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION, standard = standard)

		for rdn_item in rdn:
			self._validate_rdn_component(rdn_item)

	def _validate(self):
		all_cns = self._subject.get_all(OIDDB.RDNTypes.inverse("CN"))
		if len(all_cns) == 0:
			self._report("Enc_DER_Struct_DN_NoCN", "Certificate does not have any common name (CN) set.", commonness = Commonness.HIGHLY_UNUSUAL)
		elif len(all_cns) > 1:
			self._report("Enc_DER_Struct_DN_MultipleCN", "Certificate does have more than one common name (CN) set; in particular, %d CN fields were encountered." % (len(all_cns)), commonness = Commonness.UNUSUAL)

		seen_oid_keys = set()
		for rdn in self._subject:
			self._validate_rdn(rdn)

			oidkey = rdn.oidkey
			if oidkey in seen_oid_keys:
				oidkey_str = " + ".join(OIDDB.RDNTypes.get(oid, str(oid)) for oid in oidkey)
				self._report("Enc_DER_Struct_DN_DuplicateRDNs", "Distinguished name contains RDN element at least twice: %s (at element %s)" % (oidkey_str, rdn.pretty_str), commonness = Commonness.UNUSUAL, compatibility = Compatibility.LIMITED_SUPPORT)
			else:
				seen_oid_keys.add(oidkey)

		if self._subject.rdn_count > self._LARGE_RDN_AMOUNT:
			self._report("Enc_DER_Struct_DN_UnusuallyManyRDNs", "Distinguished name contains an unusually high amount of RDNs (%d)." % (self._subject.rdn_count), commonness = Commonness.UNUSUAL)

class DistinguishedNameValidator(BaseValidator):
	_ValidationResultClass = DistinguishedNameValidationResult
