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

from x509sak.estimate.Judgement import Commonness, Compatibility
from x509sak.estimate.Validator import BaseValidationResult, BaseValidator

class DERValidationResult(BaseValidationResult):
	def _validate(self):
		if "undecodable" in self._subject.flags:
			self._report("Enc_DER_EncodingIssues_Malformed_Undecodable", "input cannot be decoded as valid ASN.1.", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
		else:
			if "non_der" in self._subject.flags:
				self._report("Enc_DER_EncodingIssues_Malformed_NonDEREncoding", "input can be decoded ASN.1, but does not comply with Distinguished Encoding Rules (DER).", commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
			if "trailing_data" in self._subject.flags:
				self._report("Enc_DER_EncodingIssues_TrailingData", "input can de decoded as ASN.1, but has %d bytes of trailing data." % (len(self._subject.tail)), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)
			if "unexpected_type" in self._subject.flags:
				self._report("Enc_DER_EncodingIssues_Malformed_UnexpectedType", "input can be decoded as ASN.1, but not under the expected schema (instead returned %s)." % (type(self._subject.generic_asn1).__name__), commonness = Commonness.HIGHLY_UNUSUAL, compatibility = Compatibility.STANDARDS_DEVIATION)

class DERValidator(BaseValidator):
	_ValidationResultClass = DERValidationResult
