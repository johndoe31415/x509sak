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

import enum
from x509sak.Tools import JSONTools
from x509sak.Exceptions import LazyDeveloperException
from x509sak.KwargsChecker import KwargsChecker
from x509sak.estimate import ExperimentalJudgementCodes

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

class Compatibility(enum.IntEnum):
	STANDARDS_DEVIATION = 0
	LIMITED_SUPPORT = 1
	FULLY_COMPLIANT = 2

class StandardDeviationType(enum.IntEnum):
	RECOMMENDATION = 0
	VIOLATION = 1

class SecurityJudgement():
	def __init__(self, code, text, bits = None, verdict = None, commonness = None, compatibility = None, prefix_topic = False, standard = None, literature = None, info_payload = None):
		assert((code is None) or isinstance(code, ExperimentalJudgementCodes))
		assert((bits is None) or isinstance(bits, (int, float)))
		assert((verdict is None) or isinstance(verdict, Verdict))
		assert((commonness is None) or isinstance(commonness, Commonness))
		assert((compatibility is None) or isinstance(compatibility, Compatibility))
		self._code = code
		self._text = text
		self._bits = bits
		self._verdict = verdict
		self._commonness = commonness
		self._compatibility = compatibility
		self._prefix_topic = prefix_topic
		self._standard = standard
		self._literature = literature
		self._info_payload = info_payload
		if self._bits == 0:
			if self._verdict is None:
				self._verdict = Verdict.NO_SECURITY
			if self._commonness is None:
				self._commonness = Commonness.HIGHLY_UNUSUAL

	@property
	def codeenum(self):
		return self._code

	@property
	def code(self):
		return self._code.value

	@property
	def text(self):
		return self._text

	@property
	def bits(self):
		return self._bits

	@property
	def verdict(self):
		return self._verdict

	@property
	def commonness(self):
		return self._commonness

	@property
	def compatibility(self):
		return self._compatibility

	@property
	def standard(self):
		return self._standard

	@property
	def literature(self):
		return self._literature

	@property
	def info_payload(self):
		return self._info_payload

	@classmethod
	def from_dict(cls, judgement_data):
		if "code" in judgement_data:
			code = getattr(ExperimentalJudgementCodes, judgement_data["code"])
		else:
			code = None
		text = judgement_data["text"]
		bits = judgement_data.get("bits")
		verdict = judgement_data.get("verdict")
		if verdict is not None:
			verdict = Verdict(verdict["value"])
		commonness = judgement_data.get("commonness")
		if commonness is not None:
			commonness = Commonness(commonness["value"])
		compatibility = judgement_data.get("compatibility")
		if compatibility is not None:
			compatibility = Compatibility(compatibility["value"])
		standard = judgement_data.get("standard")
		if standard is not None:
			standard = StandardReference.from_dict(standard)
		literature = judgement_data.get("literature")
		if literature is not None:
			literature = LiteratureReference.from_dict(literature)
		return cls(code = code, text = text, bits = bits, verdict = verdict, commonness = commonness, compatibility = compatibility, standard = standard, literature = literature)

	def to_dict(self):
		result = {
			"code":				self.code.name,
			"topic":			self.code.topic,
			"short_text":		self.code.short_text,
			"text":				self.text,
			"bits":				self.bits,
			"verdict":			JSONTools.translate(self.verdict) if (self.verdict is not None) else None,
			"commonness":		JSONTools.translate(self.commonness) if (self.commonness is not None) else None,
			"compatibility":	JSONTools.translate(self.compatibility) if (self.compatibility is not None) else None,
			"standard":			self.standard.to_dict() if (self.standard is not None) else None,
			"literature":		self.literature.to_dict() if (self.literature is not None) else None,
		}
		return { key: value for (key, value) in result.items() if value is not None }

	def dump(self, indent = 0):
		indent_str = ("    " * indent)
		print("%s%s" % (indent_str, str(self)))

	def __str__(self):
		return "SecurityJudgement<%s / %s>" % (self.code, self.text)

class SecurityJudgements():
	def __init__(self):
		self._judgements = [ ]

	@staticmethod
	def _minof(items):
		result = None
		for item in items:
			if result is None:
				result = item
			elif item is not None:
				result = min(result, item)
		return result

	@property
	def uniform_topic(self):
		return len(set(security_judgement.code.topic for security_judgement in self)) in [ 0, 1 ]

	@property
	def bits(self):
		return self._minof(item.bits for item in self)

	@property
	def verdict(self):
		return self._minof(item.verdict for item in self)

	@property
	def commonness(self):
		return self._minof(item.commonness for item in self)

	@property
	def compatibility(self):
		return self._minof(item.compatibility for item in self)

	def summary_judgement(self):
		return SecurityJudgement(code = None, text = "Summary", bits = self.bits, verdict = self.verdict, commonness = self.commonness, compatibility = self.compatibility)

	def __iadd__(self, judgement):
		if judgement is None:
			# Simply ignore it.
			pass
		elif isinstance(judgement, SecurityJudgement):
			self._judgements.append(judgement)
		elif isinstance(judgement, SecurityJudgements):
			self._judgements += judgement
		else:
			raise NotImplementedError(judgement)
		return self

	@classmethod
	def from_dict(cls, judgements_data):
		judgements = cls()
		for judgement_data in judgements_data["components"]:
			judgements += SecurityJudgement.from_dict(judgement_data)
		return judgements

	def to_dict(self):
		result = {
			"bits":				self.bits,
			"verdict":			self.verdict,
			"commonness":		self.commonness,
			"compatibility":	self.compatibility,
			"components":		[ judgement.to_dict() for judgement in self._judgements ],
		}
		return { key: value for (key, value) in result.items() if value is not None }

	def dump(self, indent = 0):
		indent_str = ("    " * indent)
		print("%sSecurityJudgements" % (indent_str))
		for judgement in self._judgements:
			judgement.dump(indent + 1)

	def __len__(self):
		return len(self._judgements)

	def __iter__(self):
		return iter(self._judgements)

	def __getitem__(self, index):
		return self._judgements[index]

	def __str__(self):
		return "SecurityJudgements<%s>" % (", ".join(str(judgement) for judgement in self))

class StandardReference():
	_STD_TYPE = None
	_REGISTERED = { }

	@classmethod
	def from_dict(cls, data):
		if data["type"] not in cls._REGISTERED:
			raise LazyDeveloperException("Class not registered for standards type '%s'." % (data["type"]))
		return cls._REGISTERED[data["type"]].from_dict(data)

	@property
	def deviation_type(self):
		raise NotImplementedError(self.__class__.__name__)

	@classmethod
	def register(cls, decoree):
		assert(decoree._STD_TYPE is not None)
		cls._REGISTERED[decoree._STD_TYPE] = decoree
		return decoree

@StandardReference.register
class RFCReference(StandardReference):
	_STD_TYPE = "RFC"

	def __init__(self, rfcno, sect, verb, text):
		assert(verb in [ "SHOULD", "MUST", "RECOMMEND", "MAY", "SHALL" ])
		StandardReference.__init__(self)
		self._rfcno = rfcno
		self._sect = sect
		self._verb = verb
		self._text = text

	@property
	def deviation_type(self):
		return {
			"SHOULD":		StandardDeviationType.RECOMMENDATION,
			"RECOMMEND":	StandardDeviationType.RECOMMENDATION,
			"MAY":			StandardDeviationType.RECOMMENDATION,
			"MUST":			StandardDeviationType.VIOLATION,
			"SHALL":		StandardDeviationType.VIOLATION,
		}[self.verb]

	@property
	def rfcno(self):
		return self._rfcno

	@property
	def sect(self):
		return self._sect

	@property
	def verb(self):
		return self._verb

	@property
	def text(self):
		return self._text

	@classmethod
	def from_dict(cls, data):
		return cls(rfcno = data["rfcno"], sect = data["sect"], verb = data["verb"], text = data["text"])

	def to_dict(self):
		return {
			"type":				self._STD_TYPE,
			"rfcno":			self.rfcno,
			"sect":				self.sect,
			"verb":				self.verb,
			"text":				self.text,
			"deviation_type":	self.deviation_type,
		}

	def __str__(self):
		if isinstance(self.sect, str):
			return "RFC%d Sect. %s" % (self.rfcno, self.sect)
		else:
			return "RFC%d Sects. %s" % (self.rfcno, " / ".join(self.sect))

@StandardReference.register
class LiteratureReference(StandardReference):
	_STD_TYPE = "literature"
	_Arguments = KwargsChecker(required_arguments = set([ "author", "title" ]), optional_arguments = set([ "type", "year", "month", "source", "quote", "doi", "sect" ]), check_functions = {
		"year":		lambda x: isinstance(x, int),
		"month":	lambda x: isinstance(x, int) and (1 <= x <= 12),
	})

	def __init__(self, **kwargs):
		StandardReference.__init__(self)
		self._Arguments.check(kwargs, "LiteratureReference")
		self._fields = kwargs
		self._fields["type"] = self._STD_TYPE

	@property
	def deviation_type(self):
		return None

	@classmethod
	def from_dict(cls, data):
		return cls(**data)

	def to_dict(self):
		return dict(self._fields)

	def __str__(self):
		text = " and ".join(self._fields["author"])
		if self._fields["year"] is not None:
			text += " (%d)" % (self._fields["year"])
		text += ". \"%s\"" % (self._fields["title"])
		return text
