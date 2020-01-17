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

from x509sak.estimate.Judgement import SecurityJudgements

class BaseValidationResult():
	def __init__(self, validator, subject):
		self._validator = validator
		self._subject = subject
		self._result = SecurityJudgements()

	def _get_message(self, issue, message):
		return "%s %s" % (self._validtator.validation_subject, message)

	def _report(self, issue_name, message, **kwargs):
		issue = self._validator.get_error(report_name)
		if issue is None:
			return
		full_message = self._get_message(issue, message)
		self._result += SecurityJudgement(error.code, full_message, info_payload = error.info_payload, standard = error.standard, **kwargs)

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
		issue_codes = { name: ValidationIssue(code = code) for (name, code) in JudgementCode.inheritance[root_point_name].items() }
		return cls(issues = issue_codes, **kwargs)

	def get_issue(self, issue_name):
		return self._regonized_issues(issue_name)

	def validate(self, subject):
		validation_result = _ValidationResultClass(self, subject)
		return validation_result.run()
