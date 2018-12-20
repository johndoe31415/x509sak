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
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements

@BaseEstimator.register
class DistinguishedNameSecurityEstimator(BaseEstimator):
	_ALG_NAME = "dn"
	_VALID_ALPHABETS = {
		pyasn1.type.char.PrintableString:		set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"),
	}

	def _analyze_rdn_item(self, rdn_item):
		judgements = SecurityJudgements()
		asn1type = type(rdn_item.asn1)
		if asn1type in self._VALID_ALPHABETS:
			valid_chars = self._VALID_ALPHABETS[asn1type]
			illegal_chars = set(rdn_item.printable) - valid_chars
			if len(illegal_chars) > 0:
				judgements += SecurityJudgement(JudgementCode.DN_Contains_Illegal_Char, "Distinguished name contains character(s) \"%s\" which are invalid for a %s at element %s." % ("".join(sorted(illegal_chars)), asn1type.__name__, OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)

		if isinstance(rdn_item.asn1, pyasn1.type.char.TeletexString):
			judgements += SecurityJudgement(JudgementCode.DN_Contains_Deprecated_Type, "Distinguished name contains deprecated TeletexString at element %s." % (OIDDB.RDNTypes.get(rdn_item.oid, str(rdn_item.oid))), compatibility = Compatibility.STANDARDS_DEVIATION)
		return judgements

	def analyze(self, dn):
		judgements = SecurityJudgements()
		for rdn in dn:
			for rdn_item in rdn:
				judgements += self._analyze_rdn_item(rdn_item)
		return {
			"rfc2253":		dn.rfc2253_str,
			"pretty":		dn.pretty_str,
			"security":		judgements,
		}
