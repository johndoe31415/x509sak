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

import urllib.parse
from x509sak.estimate import JudgementCode, ExperimentalJudgementCodes
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, Commonness
from x509sak.ASN1Wrapper import ASN1GeneralNameWrapper
from x509sak.Tools import ValidationTools
from x509sak.Exceptions import InvalidInternalDataException

class GeneralNameValidator():
	_VALID_ERROR_TYPES = set([
		"dnsname", "dnsname_space", "dnsname_wc_notleftmost", "dnsname_wc_morethanone", "dnsname_wc_international", "dnsname_wc_broad", "dnsname_single_label",
		"ip", "ip_private",
		"email",
		"uri", "uri_invalid_scheme",
		"empty_value",
		"invalid_type",
		"unknown_subtype",
	])
	class Error():
		def __init__(self, code = None, standard = None, info_payload = None):
			self._code = code
			self._standard = standard
			self._info_payload = info_payload

		@property
		def code(self):
			return self._code

		@property
		def standard(self):
			return self._standard

		@property
		def info_payload(self):
			return self._info_payload

	def __init__(self, error_prefix_str = None, permissible_types = None, permissible_uri_schemes = None, allow_dnsname_wildcard_matches = None, errors = None):
		self._allow_dnsname_wildcard_matches = allow_dnsname_wildcard_matches
		self._error_prefix_str = error_prefix_str if (error_prefix_str is not None) else "GeneralName"
		self._errors = errors if (errors is not None) else { }
		self._permissible_types = permissible_types
		self._permissible_uri_schemes = permissible_uri_schemes
		self._validation = None
#		if len(set(self._errors) - self._VALID_ERROR_TYPES) > 0:
#			raise InvalidInternalDataException("Unsupported error type(s) passed for handling: %s" % (", ".join(sorted(set(self._errors) - self._VALID_ERROR_TYPES))))

	@classmethod
	def create_inherited(cls, root_point_name, **kwargs):
		error_codes = { name: cls.Error(code = code) for (name, code) in ExperimentalJudgementCodes.inheritance[root_point_name].items() }
		return cls(errors = error_codes, **kwargs)

	def _report_error(self, error_type, error_text, **kwargs):
		error = self._errors.get(error_type)
		if error is None:
			return

		error_text = "%s of type %s %s" % (self._error_prefix_str, self._gn.name, error_text)
		if error is None:
			self._validation += SecurityJudgement(ExperimentalJudgementCodes.X509sakIssues_AnalysisNotImplemented, error_text + " (%s)" % (error_type), **kwargs)
		else:
			self._validation += SecurityJudgement(error.code, error_text, info_payload = error.info_payload, standard = error.standard, **kwargs)

	def _handle_dNSName(self):
		self._report_error("Enc_DER_Struct_GenName_DNS_Unexpected", "contains unexpected domain name \"%s\"." % (self._gn.str_value))
		if self._gn.str_value == " ":
			return self._report_error("Enc_DER_Struct_GenName_DNS_OnlyWhitespace", "got invalid DNS name \" \" (space character).")

		if self._allow_dnsname_wildcard_matches:
			(result, label) = ValidationTools.validate_domainname_template(self._gn.str_value)
			if result != ValidationTools.DomainnameTemplateValidationResult.Valid:
				if result == ValidationTools.DomainnameTemplateValidationResult.InvalidCharacter:
					return self._report_error("Enc_DER_Struct_GenName_DNS_Malformed", "has invalid domain name \"%s\", error at label \"%s\"." % (self._gn.str_value, label))
				elif result == ValidationTools.DomainnameTemplateValidationResult.FullWildcardNotLeftmost:
					return self._report_error("Enc_DER_Struct_GenName_DNS_Wildcard_NotLeftmost", "has invalid domain name \"%s\". Full-label wildcard appears not as leftmost element." % (self._gn.str_value))
				elif result == ValidationTools.DomainnameTemplateValidationResult.MoreThanOneWildcard:
					return self._report_error("Enc_DER_Struct_GenName_DNS_Wildcard_MulitpleWildcards", "has invalid domain name \"%s\". More than one wildcard label present." % (self._gn.str_value))
				elif result == ValidationTools.DomainnameTemplateValidationResult.WildcardInInternationalDomain:
					return self._report_error("Enc_DER_Struct_GenName_DNS_Wildcard_InternationalLabel", "has invalid domain name \"%s\". Wildcard in international domain label \"%s\"." % (self._gn.str_value, label))
				else:
					raise NotImplementedError(result)

			if "*" in self._gn.str_value:
				# Wildcard match
				labels = self._gn.str_value.split(".")
				if len(labels) <= 2:
					self._report_error("Enc_DER_Struct_GenName_DNS_Wildcard_BroadMatch", "has wildcard value \"%s\", which is an extremely broad domain match." % (self._gn.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		if not "." in self._gn.str_value:
			self._report_error("Enc_DER_Struct_GenName_DNS_SingleLabel", "contains only single label \"%s\", which is highly unusual." % (self._gn.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		validation_name = self._gn.str_value
		if self._allow_dnsname_wildcard_matches:
			validation_name = validation_name.replace("*", "a")
		result = ValidationTools.validate_domainname(validation_name)
		if not result:
			self._report_error("Enc_DER_Struct_GenName_DNS_Malformed", "has invalid domain name \"%s\" (wildcard matches %s)." % (self._gn.str_value, "permitted" if self._allow_dnsname_wildcard_matches else "forbidden"))

	def _handle_iPAddress(self):
		self._report_error("Enc_DER_Struct_GenName_IPAddress_Unexpected", "contains unexpected IP address \"%s\"." % (self._gn.str_value))
		if len(self._gn.asn1_value) not in [ 4, 16 ]:
			self._report_error("Enc_DER_Struct_GenName_IPAddress_Malformed", "expects either 4 or 16 bytes of data for IPv4/IPv6, but saw %d bytes." % (len(self._gn.str_value)))
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
						self._report_error("Enc_DER_Struct_GenName_IPAddress_PrivateAddressSpace", "has network address %s in a %s subnet." % (self._gn.str_value, network_class))
						break

	def _handle_rfc822Name(self):
		self._report_error("Enc_DER_Struct_GenName_Email_Unexpected", "contains unexpected email address \"%s\"." % (self._gn.str_value))
		if not ValidationTools.validate_email_address(self._gn.str_value):
			self._report_error("Enc_DER_Struct_GenName_Email_Malformed", "contains invalid email address \"%s\"." % (self._gn.str_value))

	def _handle_directoryName(self):
		self._report_error("Enc_DER_Struct_GenName_DirectoryAddress_Unexpected", "contains unexpected directory name \"%s\"." % (self._gn.str_value))

	def _handle_uniformResourceIdentifier(self):
		self._report_error("Enc_DER_Struct_GenName_URI_Unexpected", "contains unexpected URI \"%s\"." % (self._gn.str_value))
		if not ValidationTools.validate_uri(str(self._gn.str_value)):
			self._report_error("Enc_DER_Struct_GenName_URI_Malformed", "contains invalid URI \"%s\"." % (str(self._gn.str_value)))
		if self._permissible_uri_schemes is not None:
			split_url = urllib.parse.urlsplit(self._gn.str_value)
			if split_url.scheme not in self._permissible_uri_schemes:
				self._report_error("Enc_DER_Struct_GenName_URI_UncommonURIScheme", "contains invalid URI scheme \"%s\" (permitted schemes are only %s)." % (str(self._gn.str_value), ", ".join(sorted(self._permissible_uri_schemes))))

	def _handle_registeredID(self):
		self._report_error("Enc_DER_Struct_GenName_RegisteredID_Unexpected", "contains unexpected registered ID \"%s\"." % (self._gn.str_value))

	def _do_validate(self):
#		if self._gn.str_value.strip("\t \r\n") == "":
#			self._report_error("empty_value", "has empty value or contains only of whitespace.", commonness = Commonness.HIGHLY_UNUSUAL)

#		if self._permissible_types is not None:
#			if self._gn.name not in self._permissible_types:
#				self._report_error("invalid_type", "has type that is not common or permitted in this context (allowed are %s)." % (", ".join(sorted(self._permissible_types))), commonness = Commonness.HIGHLY_UNUSUAL)

		gn_subtype_handler = getattr(self, "_handle_%s" % (str(self._gn.name)), None)
		if gn_subtype_handler is not None:
			gn_subtype_handler()
#		else:
#			self._report_error("unknown_subtype", "has no handler in %s." % (self.__class__.__name__))

	def validate(self, general_name):
		self._gn = general_name
		self._validation = SecurityJudgements()
		self._do_validate()
		return self._validation

	def validate_asn1(self, general_name_asn1):
		general_name = ASN1GeneralNameWrapper.from_asn1(general_name_asn1)
		return self.validate(general_name)
