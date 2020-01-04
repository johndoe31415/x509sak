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

import collections
import pyasn1.type.char
from x509sak.OID import OIDDB
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, Commonness, RFCReference, LiteratureReference
from x509sak.ASN1Wrapper import ASN1GeneralNameWrapper
from x509sak.Tools import ValidationTools

class GeneralNameValidator():
	class Error():
		def __init__(self, code = None, standard = None):
			self._code = code
			self._standard = standard

		@property
		def code(self):
			return self._code

		@property
		def standard(self):
			return self._standard

	def __init__(self, general_name, allow_dnsname_wildcard_matches = None, expected_types = None, error_prefix_str = None, errors = None):
		self._gn = ASN1GeneralNameWrapper.from_asn1(general_name)
		self._allow_dnsname_wildcard_matches = allow_dnsname_wildcard_matches
		self._expected_types = expected_types
		self._expected_types = set(expected_types) if (expected_types is not None) else set()
		self._error_prefix_str = error_prefix_str if (error_prefix_str is not None) else "GeneralName"
		self._errors = errors if (errors is not None) else { }
		self._validation = None

	def _raise_error(self, error_name, error_text, **kwargs):
		error = self._errors.get(error_name)
		error_text = "%s of type %s %s" % (self._error_prefix_str, self._gn.name, error_text)
		if error is None:
			self._validation += SecurityJudgement(JudgementCode.Analysis_Not_Implemented, error_text + " (%s)" % (error_name), **kwargs)
		else:
			self._validation += SecurityJudgement(error.code, error_text, standard = error.standard, **kwargs)

	def _handle_dNSName(self):
		if self._gn.str_value == " ":
			return self._raise_error("dnsname_space", "got invalid DNS name \" \" (space character).")

		if self._allow_dnsname_wildcard_matches:
			(result, label) = ValidationTools.validate_domainname_template(self._gn.str_value)
			if result != ValidationTools.DomainnameTemplateValidationResult.Valid:
				if result == ValidationTools.DomainnameTemplateValidationResult.InvalidCharacter:
					return self._raise_error("dnsname", "has invalid domain name \"%s\", error at label \"%s\"." % (self._gn.str_value, label))
				elif result == ValidationTools.DomainnameTemplateValidationResult.FullWildcardNotLeftmost:
					return self._raise_error("dnsname_wc_notleftmost", "has invalid domain name \"%s\". Full-label wildcard appears not as leftmost element." % (self._gn.str_value))
				elif result == ValidationTools.DomainnameTemplateValidationResult.MoreThanOneWildcard:
					return self._raise_error("dnsname_wc_morethanone", "has invalid domain name \"%s\". More than one wildcard label present." % (self._gn.str_value))
				elif result == ValidationTools.DomainnameTemplateValidationResult.WildcardInInternationalDomain:
					return self._raise_error("dnsname_wc_international", "has invalid domain name \"%s\". Wildcard in international domain label \"%s\"." % (self._gn.str_value, label))
				else:
					raise NotImplementedError(result)

			if "*" in self._gn.str_value:
				# Wildcard match
				labels = self._gn.str_value.split(".")
				if len(labels) <= 2:
					self._raise_error("dnsname_wc_broad", "has wildcard value \"%s\", which is an extremely broad domain match." % (self._gn.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		if not "." in self._gn.str_value:
			self._raise_error("dnsname_single_label", "contains only single label \"%s\", which is highly unusual." % (self._gn.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		validation_name = self._gn.str_value
		if self._allow_dnsname_wildcard_matches:
			validation_name = validation_name.replace("*", "a")
		result = ValidationTools.validate_domainname(validation_name)
		if not result:
			self._raise_error("dnsname", "has invalid domain name \"%s\" (wildcard matches %s)." % (self._gn.str_value, "permitted" if self._allow_dnsname_wildcard_matches else "forbidden"))

	def _handle_iPAddress(self):
		if len(self._gn.asn1_value) not in [ 4, 16 ]:
			self._raise_error("ip", "expects either 4 or 16 bytes of data for IPv4/IPv6, but saw %d bytes." % (len(self._gn.str_value)))
		else:
			if len(self._gn.asn1_value) == 4:
				# IPv4
				ip_value = int.from_bytes(self._gn.asn1_value, byteorder = "big")
				private_networks = (
					(0x0a000000, 0xff000000, "private class A"),
					(0xac100000, 0xfff00000, "private class B"),
					(0xc0a80000, 0xffff0000, "private class C"),
					(0x64400000, 0xffc00000, "carrier-grade NAT"),
					(0xe0000000, 0xf0000000, "IP multicast"),
					(0xf0000000, 0xf0000000, "reserved"),
					(0x7f000000, 0xff000000, "loopback"),
					(0xffffffff, 0xffffffff, "limited broadcast"),
				)
				for (network, netmask, network_class) in private_networks:
					if (ip_value & netmask) == network:
						self._raise_error("ip_private", "has network address %s in a %s subnet." % (self._gn.str_value, network_class))
						break

	def _handle_rfc822Name(self):
		if not ValidationTools.validate_email_address(self._gn.str_value):
			self._raise_error("email", "contains invalid email address \"%s\"." % (self._gn.str_value))

	def _handle_uniformResourceIdentifier(self):
		if not ValidationTools.validate_uri(str(self._gn.str_value)):
			self._raise_error("uri", "contains invalid URI \"%s\"." % (str(self._gn.str_value)))

	def _do_validate(self):
		if self._gn.str_value == "":
			return self._raise_error("empty", "has empty value.", commonness = Commonness.HIGHLY_UNUSUAL)

		gn_subtype_handler = getattr(self, "_handle_%s" % (str(self._gn.name)), None)
		if gn_subtype_handler is not None:
			return gn_subtype_handler()
		else:
			self._raise_error("unknown-subtype", "has no handler in %s." % (self.__class__.__name__))

		return judgements

	def validate(self):
		if self._validation is None:
			self._validation = SecurityJudgements()
			self._validation += self._do_validate()
		return self._validation

