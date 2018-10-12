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

class ConsolePrinter(object):
	def __init__(self):
		self._subs = [ ]

	def add_sub(self, text, replacement):
		self._subs.append((text, replacement))
		return self

	def add_subs(self, substitutions):
		for (text, replacement) in substitutions.items():
			self.add_sub(text, replacement)
		return self

	def sub(self, line):
		for (text, replacement) in self._subs:
			line = line.replace(text, replacement)
		return line

	def heading(self, line = "", fp = None):
		print(line, file = fp)
		print((len(line) * "-"), file = fp)

	def print(self, line = "", fp = None):
		print(self.sub(line), file = fp)
