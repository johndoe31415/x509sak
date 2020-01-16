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

from x509sak.tests import BaseTest
from x509sak.estimate.Judgement import SecurityJudgement, SecurityJudgements, JudgementCode, ExperimentalJudgementCodes, Verdict, Commonness

class SecurityJudgementTests(BaseTest):
	def test_simple(self):
		judgement = SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar!", bits = 0)
		self.assertEqual(judgement.codeenum, ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent)
		self.assertEqual(judgement.text, "Foo Bar!")
		self.assertEqual(judgement.bits, 0)
		self.assertEqual(judgement.compatibility, None)

		# The following are implied
		self.assertEqual(judgement.verdict, Verdict.NO_SECURITY)
		self.assertEqual(judgement.commonness, Commonness.HIGHLY_UNUSUAL)

		result = judgement.to_dict()
		self.assertEqual(result["code"], judgement.code.name)
		self.assertEqual(result["topic"], judgement.code.topic)
		self.assertEqual(result["short_text"], judgement.code.short_text)
		self.assertEqual(result["text"], judgement.text)
		self.assertEqual(result["bits"], judgement.bits)

	def test_judgements(self):
		judgements = SecurityJudgements()
		self.assertTrue(judgements.uniform_topic)
		self.assertEqual(len(judgements), 0)

		judgements += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 1", verdict = Verdict.HIGH, commonness = Commonness.UNUSUAL)
		self.assertTrue(judgements.uniform_topic)
		self.assertEqual(len(judgements), 1)

		judgements += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 2", verdict = Verdict.BROKEN, commonness = Commonness.COMMON)
		self.assertTrue(judgements.uniform_topic)
		self.assertEqual(len(judgements), 2)

		self.assertEqual(judgements.verdict, Verdict.BROKEN)
		self.assertEqual(judgements.commonness, Commonness.UNUSUAL)
		self.assertEqual(judgements.bits, None)

	def test_serialize_judgement(self):
		judgement = SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar!", bits = 0)
		serialized = judgement.to_dict()
		self.assertEqual(serialized["code"], judgement.code.name)
		self.assertEqual(serialized["verdict"]["name"], judgement.verdict.name)
		self.assertEqual(serialized["commonness"]["name"], judgement.commonness.name)
		self.assertNotIn("compatibility", serialized)

		judgement = SecurityJudgement.from_dict(serialized)
		self.assertEqual(judgement.codeenum, ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent)
		self.assertEqual(judgement.text, "Foo Bar!")
		self.assertEqual(judgement.bits, 0)
		self.assertEqual(judgement.verdict, Verdict.NO_SECURITY)
		self.assertEqual(judgement.commonness, Commonness.HIGHLY_UNUSUAL)
		self.assertEqual(judgement.compatibility, None)

	def test_serialize_judgements(self):
		judgements = SecurityJudgements()
		judgements += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 1", verdict = Verdict.HIGH, commonness = Commonness.UNUSUAL)
		judgements += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 2", verdict = Verdict.HIGH, commonness = Commonness.UNUSUAL)

		serialized = judgements.to_dict()
		self.assertEqual(serialized["components"][0]["text"], "Foo Bar! 1")
		self.assertEqual(serialized["components"][1]["text"], "Foo Bar! 2")

		judgements = SecurityJudgements.from_dict(serialized)
		self.assertEqual(judgements[0].text, "Foo Bar! 1")
		self.assertEqual(judgements[1].text, "Foo Bar! 2")

	def test_append_judgements(self):
		judgements = SecurityJudgements()
		self.assertEqual(len(judgements), 0)

		judgements += None
		sub = SecurityJudgements()
		sub += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 1", verdict = Verdict.HIGH, commonness = Commonness.UNUSUAL)
		sub += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 2", verdict = Verdict.HIGH, commonness = Commonness.UNUSUAL)
		judgements += sub
		self.assertEqual(len(judgements), 2)

		judgements += SecurityJudgement(code = ExperimentalJudgementCodes.X509Cert_PublicKey_RSA_ParameterFieldNotPresent, text = "Foo Bar! 3", verdict = Verdict.HIGH, commonness = Commonness.UNUSUAL)
		self.assertEqual(len(judgements), 3)

		self.assertEqual(judgements[0].text, "Foo Bar! 1")
		self.assertEqual(judgements[1].text, "Foo Bar! 2")
		self.assertEqual(judgements[2].text, "Foo Bar! 3")
