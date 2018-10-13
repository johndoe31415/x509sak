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

import tempfile
import json
from x509sak.tests import BaseTest, ResourceFileLoader
from x509sak.SubprocessExecutor import SubprocessExecutor

class CmdLineTestsExamine(BaseTest):
	def test_crt_with_custom_key_usage(self):
		with ResourceFileLoader("certs/ok/custom_key_usage.pem") as certfile:
			output = SubprocessExecutor(self._x509sak + [ "examine", certfile ]).run().stdout
			self.assertIn(b"CN = 0b239049", output)
			self.assertIn(b"CN = \"Root CA\"", output)
			self.assertIn(b"ECC on prime256v1", output)

	def test_examine_write_json(self):
		with ResourceFileLoader("certs/ok/custom_key_usage.pem") as crtfile, tempfile.NamedTemporaryFile(prefix = "crt_", suffix = ".json") as jsonfile:
			SubprocessExecutor(self._x509sak + [ "examine", "-f", "json", "-o", jsonfile.name, crtfile ]).run()
			with open(jsonfile.name) as jsonfile:
				json_data = json.load(jsonfile)
			self.assertEqual(json_data["data"][0]["issuer"]["rfc2253"], "CN=Root CA")
			self.assertEqual(json_data["data"][0]["subject"]["rfc2253"], "CN=0b239049-3d65-46c2-8fdd-90f13cadc70b")
			self.assertEqual(json_data["data"][0]["validity"]["not_before"]["iso"], "2018-07-14T16:00:53Z")
			self.assertEqual(json_data["data"][0]["validity"]["not_after"]["iso"], "2019-07-14T16:00:53Z")
