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

import math
import pyasn1
from x509sak.ModulusDB import ModulusDB
from x509sak.NumberTheory import NumberTheory
from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import JudgementCode, AnalysisOptions, Verdict, Commonness, Compatibility
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, RFCReference
from x509sak.Exceptions import LazyDeveloperException

@BaseEstimator.register
class DSASecurityEstimator(BaseEstimator):
	_ALG_NAME = "dsa"

	def analyze(self, pubkey):
		judgements = SecurityJudgements()
		result = {
			"cryptosystem":	"dsa",
			"specific": {
			},
#			"specific": {
#				"n": {
#					"bits":		pubkey.n.bit_length(),
#					"security":	self.analyze_n(pubkey.n),
#				},
#				"e": {
#					"security":	self.analyze_e(pubkey.e),
#				},
#			},
			"security": judgements,
		}

		if self._analysis_options.include_raw_data:
			result["specific"]["p"]["value"] = pubkey.p
			result["specific"]["q"]["value"] = pubkey.q
			result["specific"]["g"]["value"] = pubkey.g
			result["specific"]["pubkey"]["value"] = pubkey.pubkey
		return result
