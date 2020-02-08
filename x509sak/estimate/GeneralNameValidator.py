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
from x509sak.estimate.Judgement import Commonness, Compatibility
from x509sak.ASN1Wrapper import ASN1GeneralNameWrapper
from x509sak.Tools import ValidationTools
from x509sak.estimate.Validator import BaseValidator, BaseValidationResult
from x509sak.IPAddress import IPAddressSubnet

class GeneralNameValidationResult(BaseValidationResult):
	_PRIVATE_SUBNETS_IPV4 = (
		("current network",			IPAddressSubnet.from_str("0.0.0.0/8")),
		("private class A",			IPAddressSubnet.from_str("10.0.0.0/8")),
		("private class B",			IPAddressSubnet.from_str("172.16.0.0/12")),
		("private class C",			IPAddressSubnet.from_str("192.168.0.0/16")),
		("carrier-grade NAT",		IPAddressSubnet.from_str("100.64.0.0/10")),
		("loopback",				IPAddressSubnet.from_str("127.0.0.0/8")),
		("link-local address",		IPAddressSubnet.from_str("169.254.0.0/16")),
		("benchmarking subnet",		IPAddressSubnet.from_str("198.18.0.0/15")),
		("IP multicast",			IPAddressSubnet.from_str("224.0.0.0/4")),
		("reserved",				IPAddressSubnet.from_str("240.0.0.0/4")),
		("limited broadcast",		IPAddressSubnet.from_str("255.255.255.255/32")),
	)

	_PRIVATE_SUBNETS_IPV6 = (
		("loopback",				IPAddressSubnet.from_str("::1/128")),
		("discard",					IPAddressSubnet.from_str("100::/64")),
		("deprecated 6to4 scheme",	IPAddressSubnet.from_str("2002::/16")),
		("link-local address",		IPAddressSubnet.from_str("fc00::/7")),
		("link-local address",		IPAddressSubnet.from_str("fe80::/8")),
		("multicast address",		IPAddressSubnet.from_str("ff00::/8")),
	)

	def _get_message(self, issue, message):
		return "%s of type %s %s" % (self._validator.validation_subject, self._subject.name, message)

	def _validate_dNSName(self):
		self._report("Enc_DER_Struct_GenName_DNS_Unexpected", "contains unexpected domain name \"%s\"." % (self._subject.str_value), commonness = Commonness.UNUSUAL)
		if self._subject.str_value == " ":
			return self._report("Enc_DER_Struct_GenName_DNS_OnlyWhitespace", "got invalid DNS name \" \" (space character).", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

		if self._validator.allow_dnsname_wildcard_matches:
			(result, label) = ValidationTools.validate_domainname_template(self._subject.str_value)
			if result != ValidationTools.DomainnameTemplateValidationResult.Valid:
				if result == ValidationTools.DomainnameTemplateValidationResult.InvalidCharacter:
					return self._report("Enc_DER_Struct_GenName_DNS_Malformed", "has invalid domain name \"%s\", error at label \"%s\"." % (self._subject.str_value, label), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
				elif result == ValidationTools.DomainnameTemplateValidationResult.FullWildcardNotLeftmost:
					return self._report("Enc_DER_Struct_GenName_DNS_Wildcard_NotLeftmost", "has invalid domain name \"%s\". Full-label wildcard appears not as leftmost element." % (self._subject.str_value), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
				elif result == ValidationTools.DomainnameTemplateValidationResult.MoreThanOneWildcard:
					return self._report("Enc_DER_Struct_GenName_DNS_Wildcard_MulitpleWildcards", "has invalid domain name \"%s\". More than one wildcard label present." % (self._subject.str_value), commonness = Commonness.UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
				elif result == ValidationTools.DomainnameTemplateValidationResult.WildcardInInternationalDomain:
					return self._report("Enc_DER_Struct_GenName_DNS_Wildcard_InternationalLabel", "has invalid domain name \"%s\". Wildcard in international domain label \"%s\"." % (self._subject.str_value, label), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
				else:
					raise NotImplementedError(result)

			if "*" in self._subject.str_value:
				# Wildcard match
				labels = self._subject.str_value.split(".")
				if len(labels) <= 2:
					self._report("Enc_DER_Struct_GenName_DNS_Wildcard_BroadMatch", "has wildcard value \"%s\", which is an extremely broad domain match." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		else:
			if "*" in self._subject.str_value:
				# Not permitted but wildcard present
				self._report("Enc_DER_Struct_GenName_DNS_Wildcard_NotPermitted", "has wildcard value \"%s\", which is not permitted for this type." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		if not "." in self._subject.str_value:
			self._report("Enc_DER_Struct_GenName_DNS_SingleLabel", "contains only single label \"%s\", which is highly unusual." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

		validation_name = self._subject.str_value
		if self._validator.allow_dnsname_wildcard_matches:
			validation_name = validation_name.replace("*", "a")
		result = ValidationTools.validate_domainname(validation_name)
		if not result:
			self._report("Enc_DER_Struct_GenName_DNS_Malformed", "has invalid domain name \"%s\" (wildcard matches %s)." % (self._subject.str_value, "permitted" if self._validator.allow_dnsname_wildcard_matches else "forbidden"), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

	def _validate_iPAddress(self):
		self._report("Enc_DER_Struct_GenName_IPAddress_Unexpected", "contains unexpected IP address \"%s\"." % (self._subject.str_value), commonness = Commonness.UNUSUAL)

		address_length = len(self._subject.asn1_value)
		if (not self._validator.ip_addresses_are_subnets) and (address_length not in [ 4, 16 ]):
			self._report("Enc_DER_Struct_GenName_IPAddress_Malformed", "expects either 4 or 16 bytes of data for IPv4/IPv6, but saw %d bytes." % (len(self._subject.str_value)), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
		elif self._validator.ip_addresses_are_subnets and (address_length not in [ 8, 32 ]):
			self._report("Enc_DER_Struct_GenName_IPAddress_Malformed", "expects either 8 or 32 bytes of data for IPv4/IPv6 subnet, but saw %d bytes." % (len(self._subject.str_value)), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
		else:
			subject = self._subject.ip
			ipv4 = subject.is_ipv4
			private_subnets = self._PRIVATE_SUBNETS_IPV4 if ipv4 else self._PRIVATE_SUBNETS_IPV6
			for (network_class, subnet) in private_subnets:
				if subnet.overlaps(subject):
					self._report("Enc_DER_Struct_GenName_IPAddress_PrivateAddressSpace", "has network address %s in a %s subnet." % (str(subject), network_class), commonness = Commonness.UNUSUAL)
					break

		if self._validator.ip_addresses_are_subnets and (address_length in [ 8, 32 ]):
			if self._subject.ip.overlap:
				self._report("Enc_DER_Struct_GenName_IPAddress_MalformedSubnet", "has network address bits set which are masked by subnet: %s" % (self._subject.ip), commonness = Commonness.HIGHLY_UNUSUAL)

			if not self._subject.ip.is_cidr:
				self._report("Enc_DER_Struct_GenName_IPAddress_NonCIDRBlock", "has subnet %s that cannot be expressed as CIDR block" % (self._subject.ip), commonness = Commonness.UNUSUAL)

	def _validate_rfc822Name(self):
		self._report("Enc_DER_Struct_GenName_Email_Unexpected", "contains unexpected email address \"%s\"." % (self._subject.str_value), commonness = Commonness.UNUSUAL)
		if not ValidationTools.validate_email_address(self._subject.str_value):
			self._report("Enc_DER_Struct_GenName_Email_Malformed", "contains invalid email address \"%s\"." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

	def _validate_directoryName(self):
		self._report("Enc_DER_Struct_GenName_DirectoryAddress_Unexpected", "contains unexpected directory name \"%s\"." % (self._subject.str_value), commonness = Commonness.UNUSUAL)
		if self._subject.directory_name.rdn_count == 0:
			self._report("Enc_DER_Struct_GenName_DirectoryAddress_Empty", "contains empty directory name \"%s\"." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

	def _validate_uniformResourceIdentifier(self):
		self._report("Enc_DER_Struct_GenName_URI_Unexpected", "contains unexpected URI \"%s\"." % (self._subject.str_value))
		if not ValidationTools.validate_uri(str(self._subject.str_value)):
			self._report("Enc_DER_Struct_GenName_URI_Malformed", "contains invalid URI \"%s\"." % (str(self._subject.str_value)), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
		if self._validator.permissible_uri_schemes is not None:
			split_url = urllib.parse.urlsplit(self._subject.str_value)
			if split_url.scheme not in self._validator.permissible_uri_schemes:
				self._report("Enc_DER_Struct_GenName_URI_UncommonURIScheme", "contains invalid URI scheme \"%s\" (permitted schemes are only %s)." % (str(self._subject.str_value), ", ".join(sorted(self._validator.permissible_uri_schemes))), commonness = Commonness.UNUSUAL)

	def _validate_registeredID(self):
		self._report("Enc_DER_Struct_GenName_RegisteredID_Unexpected", "contains unexpected registered ID \"%s\"." % (self._subject.str_value), commonness = Commonness.UNUSUAL)

	def _validate_otherName(self):
		self._report("Enc_DER_Struct_GenName_OtherName_Unexpected", "contains unexpected other name \"%s\"." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

	def _validate_x400Address(self):
		self._report("Enc_DER_Struct_GenName_X400Address_Unexpected", "contains unexpected X.400 address \"%s\"." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

	def _validate_ediPartyName(self):
		self._report("Enc_DER_Struct_GenName_EDIPartyName_Unexpected", "contains unexpected EDI party name \"%s\"." % (self._subject.str_value), commonness = Commonness.HIGHLY_UNUSUAL)

	def _validate(self):
		method_name = "_validate_%s" % (str(self._subject.name))
		gn_subtype_handler = getattr(self, method_name, None)
		if gn_subtype_handler is not None:
			gn_subtype_handler()
		else:
			print(method_name)

class GeneralNameValidator(BaseValidator):
	_ValidationResultClass = GeneralNameValidationResult

	def __init__(self, validation_subject, recognized_issues, permissible_uri_schemes = None, allow_dnsname_wildcard_matches = False, ip_addresses_are_subnets = False):
		BaseValidator.__init__(self, validation_subject, recognized_issues)
		self._permissible_uri_schemes = permissible_uri_schemes
		self._allow_dnsname_wildcard_matches = allow_dnsname_wildcard_matches
		self._ip_addresses_are_subnets = ip_addresses_are_subnets

	@property
	def permissible_uri_schemes(self):
		return self._permissible_uri_schemes

	@property
	def allow_dnsname_wildcard_matches(self):
		return self._allow_dnsname_wildcard_matches

	@property
	def ip_addresses_are_subnets(self):
		return self._ip_addresses_are_subnets

	def validate_asn1(self, general_name_asn1):
		general_name = ASN1GeneralNameWrapper.from_asn1(general_name_asn1)
		return self.validate(general_name)
