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

import argparse
import enum

class KeySpecArgument(object):
	class KeySpecification(enum.IntEnum):
		RSA = 1
		ECC = 2
		HARDWARE_TOKEN = 3

	def __init__(self, keyspec_str):
		keyspec = keyspec_str.split(":")
		if len(keyspec) < 2:
			raise argparse.ArgumentTypeError("Keyspec needs to consist at least of two components, namely cryptosystem:params")

		self._cryptosystem = {
			"rsa":	self.KeySpecification.RSA,
			"ecc":	self.KeySpecification.ECC,
			"hw":	self.KeySpecification.HARDWARE_TOKEN,
		}.get(keyspec[0].lower())
		if self._cryptosystem is None:
			raise argparse.ArgumentTypeError("Unknown cryptosystem: %s" % (keyspec[0]))

		if self._cryptosystem == self.KeySpecification.RSA:
			self._bitlen = int(keyspec[1])
		elif self._cryptosystem == self.KeySpecification.ECC:
			self._curve = keyspec[1]
		elif self._cryptosystem == self.KeySpecification.HARDWARE_TOKEN:
			self._key_id = int(keyspec[1])
		else:
			raise NotImplementedError(self._cryptosystem)

	@property
	def cryptosystem(self):
		return self._cryptosystem

	@property
	def bitlen(self):
		assert(self.cryptosystem == self.KeySpecification.RSA)
		return self._bitlen

	@property
	def curve(self):
		assert(self.cryptosystem == self.KeySpecification.ECC)
		return self._curve

	@property
	def key_id(self):
		assert(self.cryptosystem == self.KeySpecification.HARDWARE_TOKEN)
		return self._key_id

	def __repr__(self):
		if self.cryptosystem == self.KeySpecification.RSA:
			return "Keyspec(%s-%d)" % (self.cryptosystem.name, self.bitlen)
		elif self.cryptosystem == self.KeySpecification.ECC:
			return "Keyspec(%s on %s)" % (self.cryptosystem.name, self.curve)
		elif self.cryptosystem == self.KeySpecification.HARDWARE_TOKEN:
			return "Keyspec(Hardware key #%d)" % (self.key_id)
		else:
			raise NotImplementedError(self.cryptosystem)

class KeyValue(object):
	def __init__(self, keyvalue_str):
		if not "=" in keyvalue_str:
			raise argparse.ArgumentTypeError("key and value need to be separated by '=' sign, i.e., key=value")
		(self._key, self._value) = keyvalue_str.split("=", maxsplit = 1)

	@property
	def key(self):
		return self._key

	@property
	def value(self):
		return self._value
