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

import os
import sys
import contextlib
import itertools
import subprocess
from x509sak.BaseAction import BaseAction
from x509sak.certgen.CertGenerator import CertGenerator

class ActionTestcaseGen(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		cg = CertGenerator.instantiate(self._args.tcname + ".ader")
		if self._args.list_parameters:
			for (name, values) in sorted(cg.parameters):
				print("%-30s %s" % (name, ", ".join(sorted(values))))
			sys.exit(0)

		template_parameters = { }
		for parameter in self._args.parameter:
			(key, value) = parameter.split("=", maxsplit = 1)
			if value == "*":
				template_parameters[key] = cg.get_choices(key)
			else:
				template_parameters[key] = [ value ]

		for (name, values) in cg.parameters:
			if name not in template_parameters:
				template_parameters[name] = values

		with contextlib.suppress(FileExistsError):
			os.makedirs(self._args.output_dir)

		template_parameters = list(template_parameters.items())
		keys = [ key for (key, values) in template_parameters ]
		values = [ values for (key, values) in template_parameters ]
		for concrete_values in itertools.product(*values):
			concrete_values = dict(zip(keys, concrete_values))
			render_result = cg.render(concrete_values)
			self._store(render_result)

	def _store(self, render_result):
		(basename, ascii_der) = render_result
		if False:
			outfile = self._args.output_dir + "/" + basename + ".ader"
			with open(outfile, "w") as f:
				f.write(ascii_der)
		else:
			outfile = self._args.output_dir + "/" + basename + ".pem"
			der_data = subprocess.check_output("ascii2der", input = ascii_der.encode())
			cert_data = subprocess.check_output([ "openssl", "x509", "-inform", "der", "-text" ], input = der_data)
			cert_data = cert_data.decode()
			cert_data = [ line.rstrip("\t ") for line in cert_data.split("\n") ]
			with open(outfile, "w") as f:
				f.write("\n".join(cert_data))
