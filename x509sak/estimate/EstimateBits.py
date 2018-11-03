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

from x509sak.estimate.BaseEstimator import BaseEstimator
from x509sak.estimate import Verdict, Commonness
from x509sak.estimate.Judgement import SecurityJudgement

@BaseEstimator.register
class BitsSecurityEstimator(BaseEstimator):
	_ALG_NAME = "bits"

	def analyze(self, code, bits):
		if bits < 64:
			judgement = SecurityJudgement(code, "Breakable with little effort (commercial-off-the-shelf hardware).", bits = bits, verdict = Verdict.NO_SECURITY, commonness = Commonness.HIGHLY_UNUSUAL, prefix_topic = True)
		elif bits < 80:
			judgement = SecurityJudgement(code, "Probably breakable with specialized hardware (limited purpose computers).", bits = bits, verdict = Verdict.WEAK, commonness = Commonness.UNUSUAL, prefix_topic = True)
		elif bits < 104:
			judgement = SecurityJudgement(code, "Nontrivial to break, but comparatively weak.", bits = bits, verdict = Verdict.WEAK, commonness = Commonness.UNUSUAL, prefix_topic = True)
		elif bits < 160:
			# 128 Bit security level
			judgement = SecurityJudgement(code, "High level of security.", bits = bits, verdict = Verdict.HIGH, commonness = Commonness.COMMON, prefix_topic = True)
		elif bits < 224:
			# 192 Bit security level
			judgement = SecurityJudgement(code, "Very high level of security.", bits = bits, verdict = Verdict.HIGH, commonness = Commonness.COMMON, prefix_topic = True)
		else:
			# 256 bit security level
			judgement = SecurityJudgement(code, "Exceptionally high level of security.", bits = bits, verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.COMMON, prefix_topic = True)
		return judgement
