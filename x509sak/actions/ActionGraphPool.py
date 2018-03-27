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

import os
import tempfile
import subprocess
from x509sak import CertificatePool
from x509sak.BaseAction import BaseAction
from x509sak.Exceptions import UnknownFormatException

class ActionGraphPool(BaseAction):
	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)
		self._pool = CertificatePool()
		self._pool.load_sources(self._args.crtsource)
		self._log.debug("Loaded a total of %d unique certificates in trust store.", self._pool.certificate_count)

		if self._args.format is not None:
			file_format = self._args.format
		else:
			file_format = os.path.splitext(self._args.outfile)[1].lstrip(".")

		if file_format == "dot":
			with open(self._args.outfile, "w") as dotfile:
				self._write_dotfile(dotfile)
		elif file_format in [ "ps", "png", "pdf" ]:
			with tempfile.NamedTemporaryFile("w", prefix = "graph_", suffix = ".dot") as dotfile, open(self._args.outfile, "wb") as outfile:
				self._write_dotfile(dotfile)
				cmd = [ "dot", "-T%s" % (file_format), dotfile.name ]
				subprocess.check_call(cmd, stdout = outfile)
		else:
			raise UnknownFormatException("Unknown file format: \"%s\"" % (file_format))

	def _write_dotfile(self, dotfile):
		def escape(text):
			text = text.replace("\\", "\\\\")
			text = text.replace("\"", "\\\"")
			return text

		def abbreviate(text, length = 30):
			if len(text) > length:
				return text[ : length - 3] + "..."
			else:
				return text

		print("digraph G {", file = dotfile)
		for cert in sorted(self._pool):
			properties = {
				"shape":	"box",
			}
			label = [
				abbreviate(cert.subject.rfc2253_str, 32),
				cert.valid_not_after.strftime("%Y-%m-%d"),
			]
			if cert.source is None:
				label.append(cert.hashval.hex()[:8])
			else:
				label.append("%s (%s)" % (cert.source, cert.hashval.hex()[:8]))

			properties["label"] = "\\n".join(escape(text) for text in label)

			if cert.is_selfsigned():
				properties["color"] = "#ff0000"
			else:
				properties["color"] = "#000000"

			node_name = "crt_" + cert.hashval.hex()
			print("	%s [ %s ];" % (node_name, ", ".join("%s = \"%s\"" % (key, value) for (key, value) in properties.items())), file = dotfile)

			issuers = self._pool.find_issuers(cert)
			for issuer in issuers:
				issuer_node_name = "crt_" + issuer.hashval.hex()
				print("	%s -> %s;" % (issuer_node_name, node_name), file = dotfile)
		print("}", file = dotfile)
		dotfile.flush()
