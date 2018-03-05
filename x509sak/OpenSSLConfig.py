#	x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#	Copyright (C) 2017-2017 Johannes Bauer
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

import collections

class OpenSSLConfig(object):
	def __init__(self):
		self._sections = collections.OrderedDict()
		self._section = None

	def new_section(self, name):
		assert(name not in self._sections)
		self._sections[name] = [ ]
		self._section = name
		return self

	def add(self, key, value):
		self._sections[self._section].append((key, value))
		return self

	def write_file(self, f = None):
		for (section_name, section_content) in self._sections.items():
			print("[%s]" % (section_name), file = f)
			for (key, value) in section_content:
				print("%s = %s" % (key, value), file = f)
			print(file = f)
