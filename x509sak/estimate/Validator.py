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

from x509sak.estimate import JudgementCode
from x509sak.estimate.Judgement import SecurityJudgements, SecurityJudgement

class BaseValidationResult():
	def __init__(self, validator, subject):
		self._validator = validator
		self._subject = subject
		self._result = SecurityJudgements()

	def _get_message(self, issue, message):
		return "%s %s" % (self._validator.validation_subject, message)

	def _report(self, issue_name, message, **kwargs):
		issue = self._validator.get_issue(issue_name)
		if issue is None:
			return
		full_message = self._get_message(issue, message)
		if "standard" not in kwargs:
			kwargs["standard"] = issue.standard
		if "info_payload" not in kwargs:
			kwargs["info_payload"] = issue.info_payload
		self._result += SecurityJudgement(issue.code, full_message, **kwargs)

	def _validate(self):
		raise NotImplementedError(__class__.__name__)

	def run(self):
		self._validate()
		return self._result

class ValidationIssue():
	def __init__(self, code = None, standard = None, info_payload = None):
		self._code = code
		self._standard = standard
		self._info_payload = info_payload

	@property
	def code(self):
		return self._code

	@property
	def standard(self):
		return self._standard

	@property
	def info_payload(self):
		return self._info_payload


class BaseValidator():
	_ValidationResultClass = None

	def __init__(self, validation_subject, recognized_issues):
		assert(isinstance(recognized_issues, dict))
		assert(all(isinstance(value, ValidationIssue) for value in recognized_issues.values()))
		self._validation_subject = validation_subject
		self._recognized_issues = recognized_issues

	@property
	def validation_subject(self):
		return self._validation_subject

	@classmethod
	def create_inherited(cls, root_point_name, **kwargs):
		recognized_issues = { name: ValidationIssue(code = code) for (name, code) in JudgementCode.inheritance[root_point_name].items() }
		return cls(recognized_issues = recognized_issues, **kwargs)

	def get_issue(self, issue_name):
		return self._recognized_issues.get(issue_name)

	def validate(self, subject):
		validation_result = self._ValidationResultClass(self, subject)
		return validation_result.run()
