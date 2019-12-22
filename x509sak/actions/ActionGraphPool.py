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
import collections
import datetime
from x509sak import CertificatePool
from x509sak.BaseAction import BaseAction
from x509sak.Exceptions import UnknownFormatException, LazyDeveloperException
from x509sak.Tools import TextTools, JSONTools
from x509sak.X509Certificate import X509CertificateClass
from x509sak.AlgorithmDB import Cryptosystems
from x509sak.AdvancedColorPalette import AdvancedColorPalette

class ActionGraphPool(BaseAction):
	_NodeAttributes = collections.namedtuple("NodeAttributes", [ "shape", "stroke_color", "fill_color", "text_color" ])
	_DefaultNodeAttributes = _NodeAttributes(shape = "box", stroke_color = "#000000", fill_color = None, text_color = "#000000")
	_NodeAttributeMap = {
		"stroke_color":		"color",
		"fill_color":		"fillcolor",
		"text_color":		"fontcolor",
	}

	def __init__(self, cmdname, args):
		BaseAction.__init__(self, cmdname, args)

		self._pool = CertificatePool()
		self._pool.load_sources(self._args.crtsource)
		self._log.debug("Loaded a total of %d unique certificates in trust store.", self._pool.certificate_count)

		if self._args.format is not None:
			file_format = self._args.format
		else:
			file_format = os.path.splitext(self._args.outfile)[1].lstrip(".")

		self._active_substitutions = { name: getattr(self, "_substitute_" + name) for name in self.get_supported_substitutions() }
		self._get_cert_attributes = getattr(self, "_get_cert_attributes_" + self._args.color_scheme, None)
		if self._get_cert_attributes is None:
			raise LazyDeveloperException("Color scheme '%s' is unsupported. This is a bug." % (self._args.color_scheme))

		# Load color palettes
		self._palette_traffic = AdvancedColorPalette(JSONTools.load_internal("x509sak.data", "palettes.json")["traffic"])
		self._palette_flatui = AdvancedColorPalette(JSONTools.load_internal("x509sak.data", "palettes.json")["flatui"])

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

		print("digraph G {", file = dotfile)
		print("	node [ fontname=\"Arial\" ];", file = dotfile)
		for cert in sorted(self._pool):
			attributes = self._get_cert_attributes(cert)
			attributes = self._NodeAttributes(*[concrete if (concrete is not None) else default for (concrete, default) in zip(attributes, self._DefaultNodeAttributes) ])
			attributes = { self._NodeAttributeMap.get(key, key): value for (key, value) in attributes._asdict().items() if (value is not None) }
			if "fillcolor" in attributes:
				attributes["style"] = "filled"

			label = self._args.label if (len(self._args.label) > 0) else self.get_default_label()
			subs = self._all_substitutions(cert)
			label = [ line % subs for line in label ]
			label = [ TextTools.abbreviate(line, to_length = self._args.abbreviate_to) for line in label ]
			attributes["label"] = "\\n".join(escape(line) for line in label)

			node_name = "crt_" + cert.hashval.hex()
			print("	%s [ %s ];" % (node_name, ", ".join("%s = \"%s\"" % (key, value) for (key, value) in attributes.items())), file = dotfile)

			issuers = self._pool.find_issuers(cert)
			for issuer in issuers:
				issuer_node_name = "crt_" + issuer.hashval.hex()
				print("	%s -> %s;" % (issuer_node_name, node_name), file = dotfile)
		print("}", file = dotfile)
		dotfile.flush()

	def _get_cert_attributes_expiration(self, crt):
		now = datetime.datetime.utcnow()
		if now < crt.valid_not_before:
			# Not valid yet
			return self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("peter-river"), stroke_color = None, text_color = None)
		elif now > crt.valid_not_after:
			# Already expired
			return self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("pomegranate"), stroke_color = None, text_color = None)
		else:
			still_valid_days = ((crt.valid_not_after - now).total_seconds()) / 86400
			coefficient = still_valid_days / 100
			color = self._palette_traffic.get_hex_color(coefficient)
			return self._NodeAttributes(shape = None, fill_color = color, stroke_color = None, text_color = None)

	def _get_cert_attributes_certtype(self, crt):
		classification = crt.classify()
		return {
			X509CertificateClass.CARoot:			self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("sun-flower"), stroke_color = None, text_color = None),
			X509CertificateClass.CAIntermediate:	self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("orange"), stroke_color = None, text_color = None),
			X509CertificateClass.ClientServerAuth:	self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("amethyst"), stroke_color = None, text_color = None),
			X509CertificateClass.ClientAuth:		self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("emerland"), stroke_color = None, text_color = None),
			X509CertificateClass.ServerAuth:		self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("peter-river"), stroke_color = None, text_color = None),
		}.get(classification, self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("concrete"), stroke_color = None, text_color = None))

	def _color_cryptosystem(self, cryptosystem):
		return {
			Cryptosystems.RSA:			self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("peter-river"), stroke_color = None, text_color = None),
			Cryptosystems.ECC_ECDSA:	self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("emerland"), stroke_color = None, text_color = None),
			Cryptosystems.ECC_EdDSA:	self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("orange"), stroke_color = None, text_color = None),
		}.get(cryptosystem, self._NodeAttributes(shape = None, fill_color = self._palette_flatui.get_hex_color("concrete"), stroke_color = None, text_color = None))

	def _get_cert_attributes_keytype(self, crt):
		return self._color_cryptosystem(crt.pubkey.pk_alg.value.cryptosystem)

	def _get_cert_attributes_sigtype(self, crt):
		signature_function = crt.signature_algorithm.value.sig_fnc.value
		cryptosystem = signature_function.cryptosystem
		return self._color_cryptosystem(cryptosystem)

	def _substitute_derhash(self, crt):
		return crt.hashval.hex()[:8]

	def _substitute_filename(self, crt):
		return crt.source

	def _substitute_filebasename(self, crt):
		return os.path.basename(crt.source)

	def _substitute_subject(self, crt):
		return crt.subject.pretty_str

	def _substitute_subject_rfc2253(self, crt):
		return crt.subject.rfc2253_str

	def _substitute_valid_not_after(self, crt):
		return crt.valid_not_after.strftime("%Y-%m-%d")

	def _all_substitutions(self, crt):
		return { name: handler(crt) for (name, handler) in self._active_substitutions.items() }

	@classmethod
	def get_supported_substitutions(cls):
		for methodname in dir(cls):
			if methodname.startswith("_substitute_"):
				yield methodname[12:]

	@classmethod
	def get_supported_colorschemes(cls):
		for methodname in dir(cls):
			if methodname.startswith("_get_cert_attributes_"):
				yield methodname[21:]

	@classmethod
	def get_default_label(cls):
		return [
			"%(filebasename)s (%(derhash)s)",
			"%(subject)s",
			"%(valid_not_after)s",
		]
