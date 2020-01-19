#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2020-2020 Johannes Bauer
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

from x509sak.estimate.Judgement import Commonness, Compatibility
from x509sak.estimate.Validator import BaseValidationResult, BaseValidator
from x509sak.estimate.GeneralNameValidator import GeneralNameValidator

class NameConstraintsSubtreeValidationResult(BaseValidationResult):

	def _validate_subtree(self, subtree):
		if subtree.minimum != 0:
			self._report("X509Cert_Body_X509Exts_Ext_NC_SubtreeTemplate_MinimumNotZero", "contains minimum value that is not zero, but %d." % (subtree.minimum))
		if subtree.maximum is not None:
			self._report("X509Cert_Body_X509Exts_Ext_NC_SubtreeTemplate_MaximumPresent", "contains maximum value that is present and %d." % (subtree.maximum))

		self._delegate(self._validator.base_name_validator, subtree.base)

	def _validate(self):
		for subtree in self._subject:
			self._validate_subtree(subtree)

class NameConstraintsSubtreeValidator(BaseValidator):
	_ValidationResultClass = NameConstraintsSubtreeValidationResult

	def __init__(self, validation_subject, recognized_issues):
		BaseValidator.__init__(self, validation_subject, recognized_issues)
		self._base_name_validator = GeneralNameValidator(validation_subject = validation_subject, recognized_issues = recognized_issues, allow_dnsname_wildcard_matches = True, ip_addresses_are_subnets = True, permissible_uri_schemes = [ "http", "https", "ldap" ])

	@property
	def base_name_validator(self):
		return self._base_name_validator
