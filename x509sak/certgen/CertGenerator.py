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
import mako.lookup
from x509sak.OID import OID, OIDDB
from x509sak.BijectiveDict import BijectiveDict

class CertGeneratorHelper():
	_Exported_Extension_OIDs = BijectiveDict({
		OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"):		"SKI",
		OIDDB.X509Extensions.inverse("KeyUsage"):					"KU",
		OIDDB.X509Extensions.inverse("SubjectAlternativeName"):		"SAN",
		OIDDB.X509Extensions.inverse("IssuerAlternativeName"):		"IAN",
		OIDDB.X509Extensions.inverse("BasicConstraints"):			"BC",
		OIDDB.X509Extensions.inverse("NameConstraints"):			"NC",
		OIDDB.X509Extensions.inverse("CRLDistributionPoints"):		"CRLDP",
		OIDDB.X509Extensions.inverse("CertificatePolicies"):		"CP",
		OIDDB.X509Extensions.inverse("AuthorityKeyIdentifier"):		"AKI",
		OIDDB.X509Extensions.inverse("PolicyConstraints"):			"PC",
		OIDDB.X509Extensions.inverse("ExtendedKeyUsage"):			"EKU",
		OIDDB.X509Extensions.inverse("NetscapeCertificateType"):	"NSCT",
	})

	@classmethod
	def known_extension_oids(cls):
		return [ str(oid) for oid in cls._Exported_Extension_OIDs.keys() ]

	@classmethod
	def extension_oid_abbreviation(cls, oid):
		if oid is None:
			return None
		return cls._Exported_Extension_OIDs.get(OID.from_str(oid))

class CertGenerator():
	def __init__(self, template):
		self._template = template
		self._parameters = { }
		self._template.render(**{
			"p":						lambda name: None,
			"h":						CertGeneratorHelper,
			"declare_parameter":		self._declare_parameter,
			"export_var":				lambda x, y: None,
			"import_vars":				lambda *x: None,
			"error":					lambda *x: None,
		})

	@classmethod
	def instantiate(cls, template_name):
		base_path = os.path.dirname(__file__) + "/templates/"
		lookup = mako.lookup.TemplateLookup([ base_path + "testcases", base_path + "blocks" ], strict_undefined = True, input_encoding = "utf-8")
		template = lookup.get_template(template_name)
		return cls(template)

	@property
	def parameters(self):
		return iter(self._parameters.items())

	def get_choices(self, name):
		return self._parameters[name]

	def _get_known_extension_oids(self):
		return [ str(oid) for oid in OIDDB.X509Extensions.keys() ]

	def _declare_parameter(self, name, choices):
		self._parameters[name] = choices

	def render(self, parameters):
		missing_keys = set(self._parameters.keys()) - set(parameters.keys())
		if len(missing_keys) > 0:
			raise Exception("Need to supply: %s" % (", ".join(sorted(missing_keys))))

		exported_vars = { }
		def export_var(varname, value):
			exported_vars[varname] = value

		def import_vars(*names):
			if len(names) == 1:
				return exported_vars[names[0]]
			else:
				return [ exported_vars[name] for name in names ]

		def error(*args):
			raise Exception(*args)

		result = self._template.render(**{
			"p":						lambda name: parameters.get(name),
			"h":						CertGeneratorHelper,
			"declare_parameter":		lambda x, y: None,
			"export_var":				export_var,
			"import_vars":				import_vars,
			"error":					error,
		})
		return (exported_vars["filename"], result)
