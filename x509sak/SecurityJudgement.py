#       x509sak - The X.509 Swiss Army Knife white-hat certificate toolkit
#       Copyright (C) 2018-2018 Johannes Bauer
#
#       This file is part of x509sak.
#
#       x509sak is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; this program is ONLY licensed under
#       version 3 of the License, later versions are explicitly excluded.
#
#       x509sak is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with x509sak; if not, write to the Free Software
#       Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#       Johannes Bauer <JohannesBauer@gmx.de>

import enum

class Verdict(enum.IntEnum):
	NO_SECURITY = 0
	BROKEN = 1
	WEAK = 2
	MEDIUM = 3
	HIGH = 4
	BEST_IN_CLASS = 5

class Commonness(enum.IntEnum):
	HIGHLY_UNUSUAL = 0
	UNUSUAL = 1
	FAIRLY_COMMON = 2
	COMMON = 3

class SecurityJudgement(object):
	def __init__(self, topic, text, bits = None, verdict = None, commonness = None):
		assert((bits is None) or isinstance(bits, (int, float)))
		assert((verdict is None) or isinstance(verdict, Verdict))
		assert((commonness is None) or isinstance(commonness, Commonness))
		self._topic = topic
		self._text = text
		self._bits = bits
		self._verdict = verdict
		self._commonness = commonness
		if self._bits == 0:
			if self._verdict is None:
				self._verdict = Verdict.NO_SECURITY
			if self._commonness is None:
				self._commonness = Commonness.HIGHLY_UNUSUAL

	@property
	def component_cnt(self):
		return 1

	@property
	def topic(self):
		return self._topic

	@property
	def text(self):
		return self._text

	@property
	def topic_text(self):
		return "%s: %s" % (self.topic, self.text)

	@property
	def bits(self):
		return self._bits

	@property
	def verdict(self):
		return self._verdict

	@property
	def commonness(self):
		return self._commonness

	def to_dict(self):
		result = {
			"topic":		self.topic,
			"text":			self.text,
			"bits":			self.bits,
			"verdict":		self.verdict,
			"commonness":	self.commonness,
		}
		return { key: value for (key, value) in result.items() if value is not None }

class SecurityJudgements(object):
	def __init__(self):
		self._judgements = [ ]

	@property
	def component_cnt(self):
		return sum(judgement.component_cnt for judgement in self._judgements)

	@staticmethod
	def _minof(a, b):
		if (a is None) and (b is None):
			return None
		elif (a is not None) and (b is not None):
			# Take minimum
			return min(a, b)
		elif b is None:
			return a
		else:
			return b

	@property
	def text(self):
		return " / ".join(component.topic_text for component in self._judgements)

	@property
	def topic_text(self):
		return self.text

	@property
	def bits(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.bits)
		return result

	@property
	def verdict(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.verdict)
		return result

	@property
	def commonness(self):
		result = None
		for judgement in self._judgements:
			result = self._minof(result, judgement.commonness)
		return result

	def __iadd__(self, judgement):
		assert(isinstance(judgement, (SecurityJudgement, SecurityJudgements)))
		self._judgements.append(judgement)
		return self

	def _clone(self):
		clone = SecurityJudgements()
		for item in self._judgements:
			if isinstance(item, SecurityJudgement):
				clone += item
			else:
				clone += item._clone()
		return clone

	def __add__(self, judgement):
		clone = self._clone()
		clone += judgement
		return clone

	def to_dict(self):
		result = {
			"text":			self.text,
			"bits":			self.bits,
			"verdict":		self.verdict,
			"commonness":	self.commonness,
			"components":	self._judgements,
		}
		return { key: value for (key, value) in result.items() if value is not None }

	def __iter__(self):
		for item in self._judgements:
			if isinstance(item, SecurityJudgement):
				yield item
			else:
				yield from item
