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

import enum
import math
import calendar
import datetime
import pyasn1.codec.der.decoder
from x509sak.NumberTheory import NumberTheory
from x509sak.ModulusDB import ModulusDB
from x509sak.OID import OIDDB, OID
from x509sak.Exceptions import LazyDeveloperException, UnknownAlgorithmException
from x509sak.AlgorithmDB import HashFunctions, SignatureAlgorithms
from x509sak.SecurityJudgement import JudgementCode, SecurityJudgements, SecurityJudgement, Verdict, Commonness
import x509sak.ASN1Models as ASN1Models

class AnalysisOptions(object):
	class RSATesting(enum.IntEnum):
		Full = 0
		Some = 1
		Fast = 2

	class CertificatePurpose(enum.Enum):
		CACertificate = "ca"
		TLSServerCertificate = "tls-server"
		TLSClientCertificate = "tls-client"

	def __init__(self, rsa_testing = RSATesting.Full, include_raw_data = False, purposes = None, fqdn = None):
		assert(isinstance(rsa_testing, self.RSATesting))
		self._rsa_testing = rsa_testing
		self._include_raw_data = include_raw_data
		self._purposes = purposes
		self._fqdn = fqdn

	@property
	def rsa_testing(self):
		return self._rsa_testing

	@property
	def include_raw_data(self):
		return self._include_raw_data

	@property
	def purposes(self):
		return self._purposes

	@property
	def fqdn(self):
		return self._fqdn

class SecurityEstimator(object):
	_KNOWN_ALGORITHMS = { }
	_ALG_NAME = None

	def __init__(self, analysis_options = None):
		if analysis_options is None:
			analysis_options = AnalysisOptions()
		self._analysis_options = analysis_options

	@classmethod
	def register(cls, estimator_class):
		alg_name = estimator_class._ALG_NAME
		if alg_name is None:
			raise Exception("No algorithm name defined to register by.")
		if alg_name in cls._KNOWN_ALGORITHMS:
			raise Exception("Trying to re-register algorithm: %s" % (alg_name))
		cls._KNOWN_ALGORITHMS[alg_name] = estimator_class

	@classmethod
	def algorithm(cls, alg_name, analysis_options = None):
		if alg_name not in cls._KNOWN_ALGORITHMS:
			raise KeyError("Algorithm quality of '%s' cannot be estimated, Estimator class not registered." % (alg_name))
		return cls._KNOWN_ALGORITHMS[alg_name](analysis_options = analysis_options)

	def analyze(self, *args, **kwargs):
		raise NotImplementedError("method 'analyze'")


class BitsSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "bits"

	def analyze(self, code, bits):
		if bits < 64:
			judgement = SecurityJudgement(code, "Breakable with little effort (commercial-off-the-shelf hardware).", bits = bits, verdict = Verdict.NO_SECURITY, commonness = Commonness.HIGHLY_UNUSUAL)
		elif bits < 80:
			judgement = SecurityJudgement(code, "Probably breakable with specialized hardware (limited purpose computers).", bits = bits, verdict = Verdict.WEAK, commonness = Commonness.UNUSUAL)
		elif bits < 104:
			judgement = SecurityJudgement(code, "Nontrivial to break, but comparatively weak.", bits = bits, verdict = Verdict.WEAK, commonness = Commonness.UNUSUAL)
		elif bits < 160:
			# 128 Bit security level
			judgement = SecurityJudgement(code, "High level of security.", bits = bits, verdict = Verdict.HIGH, commonness = Commonness.COMMON)
		elif bits < 224:
			# 192 Bit security level
			judgement = SecurityJudgement(code, "Very high level of security.", bits = bits, verdict = Verdict.HIGH, commonness = Commonness.COMMON)
		else:
			# 256 bit security level
			judgement = SecurityJudgement(code, "Exceptionally high level of security.", bits = bits, verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.COMMON)
		return judgement
SecurityEstimator.register(BitsSecurityEstimator)


class RSASecurityEstimator(SecurityEstimator):
	_ALG_NAME = "rsa"

	def __init__(self, analysis_options = None):
		super().__init__(analysis_options = analysis_options)
		if self._analysis_options.rsa_testing == AnalysisOptions.RSATesting.Full:
			self._test_probable_prime = True
			self._pollards_rho_iterations = 10000
		elif self._analysis_options.rsa_testing == AnalysisOptions.RSATesting.Some:
			self._test_probable_prime = False
			self._pollards_rho_iterations = 5
		elif self._analysis_options.rsa_testing == AnalysisOptions.RSATesting.Fast:
			self._test_probable_prime = False
			self._pollards_rho_iterations = 0
		else:
			raise LazyDeveloperException(NotImplemented, self._analysis_options.rsa_testing)

	@staticmethod
	def analyze_e(e):
		if e == 1:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Is_0x1, "RSA exponent is 1, this is a malicious key.", bits = 0)
		elif e in [ 3, 5, 7, 17, 257 ]:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Small, "RSA exponent is small, but fairly common.", verdict = Verdict.MEDIUM, commonness = Commonness.FAIRLY_COMMON)
		elif e < 65537:
			return SecurityJudgement(JudgementCode.RSA_Exponent_SmallUnusual, "RSA exponent is small and an uncommon choice.", verdict = Verdict.MEDIUM, commonness = Commonness.UNUSUAL)
		elif e == 65537:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Is_0x10001, "RSA exponent is the most common choice.", verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.COMMON)
		else:
			return SecurityJudgement(JudgementCode.RSA_Exponent_Large, "RSA exponent is uncommonly large. This need not be a weakness, but is highly unusual and may cause interoperability issues.", verdict = Verdict.BEST_IN_CLASS, commonness = Commonness.HIGHLY_UNUSUAL)

	def analyze_n(self, n):
		judgements = SecurityJudgements()

		if self._test_probable_prime:
			if NumberTheory.is_probable_prime(n):
				judgements += SecurityJudgement(JudgementCode.RSA_Modulus_Prime, "Modulus is prime, not a compound integer as we would expect for RSA.", bits = 0)

		if self._pollards_rho_iterations > 0:
			small_factor = NumberTheory.pollard_rho(n, max_iterations = self._pollards_rho_iterations)
			if small_factor is not None:
				judgements += SecurityJudgement(JudgementCode.RSA_Modulus_Factorable, "Modulus has small factor (%d) and is therefore trivially factorable." % (small_factor), bits = 0)

		match = ModulusDB().find(n)
		if match is not None:
			judgements += SecurityJudgement(JudgementCode.RSA_Modulus_FactorizationKnown, "Modulus is known to be compromised: %s" % (match.text), bits = 0)

		judgement = None
		hweight_analysis = NumberTheory.hamming_weight_analysis(n)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.RSA_Modulus_BitBias, "Modulus does not appear to be random. Expected a Hamming weight between %d and %d for a %d bit modulus, but found Hamming weight %d." % (hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight, hweight_analysis.bitlen, hweight_analysis.hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		# We estimate the complexity of factoring the modulus by the asymptotic
		# complexity of the GNFS.
		log2_n = n.bit_length()
		log_n = log2_n * math.log(2)
		bits_security = 2.5596 * (log_n ** (1/3)) * (math.log(log_n) ** (2/3))
		bits_security = math.floor(bits_security)
		judgements += self.algorithm("bits").analyze(JudgementCode.RSA_Modulus_Length, bits_security)

		return judgements

	def analyze(self, pubkey):
		result = {
			"cryptosystem":	"rsa",
			"specific": {
				"n": {
					"bits":		pubkey.n.bit_length(),
					"security":	self.analyze_n(pubkey.n),
				},
				"e": {
					"security":	self.analyze_e(pubkey.e),
				},
			}
		}
		result["security"] = result["specific"]["n"]["security"] + result["specific"]["e"]["security"]
		if self._analysis_options.include_raw_data:
			result["n"]["value"] = pubkey.n
			result["e"]["value"] = pubkey.e
		return result
SecurityEstimator.register(RSASecurityEstimator)


class ECCSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "ecc"
	def analyze(self, pubkey):
		curve = pubkey.curve
		judgements = SecurityJudgements()

		# Check that the encoded public key point is on curve first
		Q = curve.point(pubkey.x, pubkey.y)
		if not Q.on_curve():
			return SecurityJudgement(JudgementCode.ECC_Pubkey_Not_On_Curve, "Public key point Q is not on the underlying curve %s." % (pubkey.curve), bits = 0)

		# Check that the encoded public key is not Gx
		if Q.x == curve.Gx:
			return SecurityJudgement(JudgementCode.ECC_Pubkey_Is_G, "Public key point Q_x is equal to generator G_x on curve %s." % (pubkey.curve), bits = 0)

		# We assume, completely out-of-the-blue and worst-case estimate, 32
		# automorphisms that could be present for any curve (see Duursma et
		# al., "Speeding up the discrete log computation on curves with
		# automorphisms"). Therefore, for a given order n, we estimate the
		# complexity in bits as:
		#
		# b = log2(sqrt(n / 32)) = (log2(n) / 2) - 2.5
		approx_curve_order_bits = math.log(curve.n, 2)
		bits_security = (approx_curve_order_bits / 2) - 2.5
		bits_security = math.floor(bits_security)
		judgements += self.algorithm("bits").analyze(JudgementCode.ECC_Pubkey_CurveOrder, bits_security)

		# Check if the affine X/Y coordinates of the public key are about the
		# same length as the curve order. If randomly generated, both X and Y
		# should be about the same bitlength as the generator order and the
		# hamming weight should be roughly half of the bitlength of the curve
		# order.
		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.x, min_bit_length = curve.field_bits)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.ECC_Pubkey_X_BitBias, "Hamming weight of public key field element's X coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		hweight_analysis = NumberTheory.hamming_weight_analysis(pubkey.y, min_bit_length = curve.field_bits)
		if not hweight_analysis.plausibly_random:
			judgements += SecurityJudgement(JudgementCode.ECC_Pubkey_Y_BitBias, "Hamming weight of public key field element's Y coordinate is %d at bitlength %d, but expected a weight between %d and %d when randomly chosen; this is likely not coincidential." % (hweight_analysis.hweight, hweight_analysis.bitlen, hweight_analysis.rnd_min_hweight, hweight_analysis.rnd_max_hweight), commonness = Commonness.HIGHLY_UNUSUAL)

		return {
			"cryptosystem":		"ecc/ecdsa",
			"specific":	{
				"curve":		curve.name,
			},
			"security":			judgements,
		}
SecurityEstimator.register(ECCSecurityEstimator)

class CrtValiditySecurityEstimator(SecurityEstimator):
	_ALG_NAME = "crt_validity"

	def _format_datetime(self, dt):
		return {
			"iso":		dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
			"timet":	calendar.timegm(dt.utctimetuple()),
		}

	def analyze(self, certificate):
		not_before = certificate.valid_not_before
		not_after = certificate.valid_not_after
		is_ca = certificate.is_ca_certificate
		judgements = SecurityJudgements()

		now = datetime.datetime.utcnow()
		if not_before > not_after:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_NeverValid, "'Not before' timestamp is greater than 'not after' timestamp. Certificate is always invalid.", bits = 0)
		elif now < not_before:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_NotYetValid, "Certificate is not yet valid, becomes valid in the future.", bits = 0, commonness = Commonness.UNUSUAL)
		elif now > not_after:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_Expired, "Certificate has expired.", bits = 0, commonness = Commonness.COMMON)
		else:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_Valid, "Certificate is currently valid.", commonness = Commonness.COMMON)

		validity_days = ((not_after - not_before).total_seconds()) / 86400

		if not is_ca:
			margins = [ 2 * 365.25, 5 * 365.25, 7 * 365.25 ]
		else:
			margins = [ 12.5 * 365.25, 25 * 365.25, 30 * 365.25 ]

		crt_type = "CA" if is_ca else "non-CA"
		if validity_days < margins[0]:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_Length_Conservative, "Lifetime is conservative for %s certificate." % (crt_type), commonness = Commonness.COMMON, verdict = Verdict.BEST_IN_CLASS)
		elif validity_days < margins[1]:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_Length_Long, "Lifetime is long, but still acceptable for %s certificate." % (crt_type), commonness = Commonness.COMMON, verdict = Verdict.HIGH)
		elif validity_days < margins[2]:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_Length_VeryLong, "Lifetime is very long for %s certificate." % (crt_type), commonness = Commonness.UNUSUAL, verdict = Verdict.MEDIUM)
		else:
			judgements += SecurityJudgement(JudgementCode.Cert_Validity_Length_ExceptionallyLong, "Lifetime is exceptionally long for %s certificate." % (crt_type), commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.WEAK)

		return {
			"not_before":		self._format_datetime(not_before),
			"not_after":		self._format_datetime(not_after),
			"validity_days":	validity_days,
			"security":			judgements,
		}

SecurityEstimator.register(CrtValiditySecurityEstimator)


class SignatureSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "sig"

	def analyze(self, signature_alg_oid, signature_alg_params, signature):
		signature_alg = SignatureAlgorithms.lookup("oid", signature_alg_oid)
		if signature_alg is None:
			raise UnknownAlgorithmException("Unsupported signature algorithm used (OID %s), cannot make security determination." % (signature_alg_oid))

		if signature_alg.value.hash_fnc is not None:
			# Signature algorithm requires a particular hash function
			hash_fnc = signature_alg.value.hash_fnc
		elif signature_alg == SignatureAlgorithms.RSASSA_PSS:
			# Need to look at parameters to determine hash function
			(asn1, tail) = pyasn1.codec.der.decoder.decode(signature_alg_params, asn1Spec = ASN1Models.RSASSA_PSS_Params())
			if asn1["hashAlgorithm"].hasValue():
				hash_oid = OID.from_str(str(asn1["hashAlgorithm"]["algorithm"]))
				hash_fnc = HashFunctions.lookup("oid", hash_oid)
				if hash_fnc is None:
					raise UnknownAlgorithmException("Unsupported hash algorithm used for RSA-PSS (OID %s), cannot make security determination." % (hash_oid))
			else:
				# Default for RSASSA-PSS is SHA-1
				hash_fnc = HashFunctions["sha1"]
		else:
			raise LazyDeveloperException("Unable to determine hash function for signature algorithm %s." % (signature_alg.name))

		result = {
			"name":			signature_alg.name,
			"pretty":		signature_alg.value.sig_fnc.value.pretty_name + " with " + signature_alg.value.hash_fnc.value.pretty_name,
			"sig_fnc":		self.algorithm("sig_fnc", analysis_options = self._analysis_options).analyze(signature_alg.value.sig_fnc),
			"hash_fnc":		self.algorithm("hash_fnc", analysis_options = self._analysis_options).analyze(hash_fnc),
		}
		result["security"] = SecurityJudgements()
		result["security"] += result["sig_fnc"]["security"]
		result["security"] += result["hash_fnc"]["security"]
		return result

SecurityEstimator.register(SignatureSecurityEstimator)


class CrtExtensionsSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "crt_exts"

	def _analyze_extension(self, extension):
		return {
			"name":		extension.name,
			"oid":		str(extension.oid),
			"known":	extension.known,
		}

	def _judge_uniqueness(self, extensions):
		have_oids = set()

		for extension in extensions:
			if extension.oid in have_oids:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_Duplicate, "X.509 extension %s (OID %s) is present at least twice. This is a direct violation of RFC5280, Sect. 4.2." % (extension.name, str(extension.oid)), bits = 0)
			have_oids.add(extension.oid)
		else:
			judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_All_Unique, "All X.509 extensions are unique.", commonness = Commonness.COMMON)
		return judgement

	def _judge_basic_constraints(self, extensions):
		bc = extensions.get_first(OIDDB.X509Extensions.inverse("BasicConstraints"))
		if bc is None:
			judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_BasicConstraints_Missing, "BasicConstraints extension is missing.", commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			if not bc.critical:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_BasicConstraints_PresentButNotCritical, "BasicConstraints extension is present, but not marked as critical.", commonness = Commonness.UNUSUAL)
			else:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_BasicConstraints_PresentAndCritical, "BasicConstraints extension is present and marked as critical.", commonness = Commonness.COMMON)
		return judgement

	def _judge_subject_key_identifier(self, pubkey, extensions):
		ski = extensions.get_first(OIDDB.X509Extensions.inverse("SubjectKeyIdentifier"))
		if ski is None:
			judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_Missing, "SubjectKeyIdentifier extension is missing.", commonness = Commonness.UNUSUAL)
		else:
			check_hashfncs = [ HashFunctions.sha1, HashFunctions.sha256, HashFunctions.sha224, HashFunctions.sha384, HashFunctions.sha512, HashFunctions.md5, HashFunctions.sha3_256, HashFunctions.sha3_384, HashFunctions.sha3_512 ]
			tried_hashfncs = [ ]
			cert_ski = ski.keyid
			for hashfnc in check_hashfncs:
				try:
					computed_ski = pubkey.keyid(hashfnc = hashfnc.name)
					if cert_ski == computed_ski:
						if hashfnc == HashFunctions.sha1:
							judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_SHA1, "SubjectKeyIdentifier present and matches SHA-1 of contained public key.", commonness = Commonness.COMMON)
						else:
							judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_OtherHash, "SubjectKeyIdentifier present and matches %s of contained public key." % (hashfnc.value.pretty_name), commonness = Commonness.UNUSUAL)
						break
					tried_hashfncs.append(hashfnc)
				except ValueError:
					pass
			else:
				judgement = SecurityJudgement(JudgementCode.Cert_X509Ext_SubjectKeyIdentifier_Arbitrary, "SubjectKeyIdentifier key ID (%s) does not match any tested cryptographic hash function (%s) over the contained public key." % (ski.keyid.hex(), ", ".join(hashfnc.value.pretty_name for hashfnc in tried_hashfncs)), commonness = Commonness.HIGHLY_UNUSUAL)
		return judgement


	def analyze(self, certificate):
		extensions = certificate.get_extensions()

		individual = [ ]
		for extension in extensions:
			individual.append(self._analyze_extension(extension))

		judgements = SecurityJudgements()
		judgements += self._judge_uniqueness(extensions)
		judgements += self._judge_basic_constraints(extensions)
		judgements += self._judge_subject_key_identifier(certificate.pubkey, extensions)

		return {
			"individual":	individual,
			"security":		judgements,
		}
SecurityEstimator.register(CrtExtensionsSecurityEstimator)

class SignatureFunctionSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "sig_fnc"

	def analyze(self, sig_fnc):
		judgements = SecurityJudgements()
		if sig_fnc.value.name == "rsa-ssa-pss":
			judgements += SecurityJudgement(JudgementCode.SignatureFunction_UncommonPaddingScheme, "Not widely used padding scheme for RSA.", commonness = Commonness.UNUSUAL)
		elif sig_fnc.value.name == "eddsa":
			judgements += SecurityJudgement(JudgementCode.SignatureFunction_UncommonCryptosystem, commonness = Commonness.UNUSUAL, verdict = Verdict.BEST_IN_CLASS)
		else:
			judgements += SecurityJudgement(JudgementCode.SignatureFunction_Common, "Commonly used signature function.", commonness = Commonness.COMMON)

		return {
			"name":			sig_fnc.name,
			"pretty":		sig_fnc.value.pretty_name,
			"security":		judgements,
		}
SecurityEstimator.register(SignatureFunctionSecurityEstimator)


class HashFunctionSecurityEstimator(SecurityEstimator):
	_ALG_NAME = "hash_fnc"

	def analyze(self, hash_fnc):
		if hash_fnc.value.derating is None:
			bits_security = hash_fnc.value.output_bits / 2
		else:
			bits_security = hash_fnc.value.derating.security_lvl_bits

		judgements = SecurityJudgements()
		judgements += self.algorithm("bits", analysis_options = self._analysis_options).analyze(JudgementCode.HashFunction_Length, bits_security)
		if hash_fnc.value.derating is not None:
			judgements += SecurityJudgement(JudgementCode.HashFunction_Derated, "Derated from ideal %d bits security level because of %s." % (hash_fnc.value.output_bits / 2, hash_fnc.value.derating.reason))

		result = {
			"name":			hash_fnc.value.name,
			"pretty":		hash_fnc.value.pretty_name,
			"bitlen":		hash_fnc.value.output_bits,
			"security":		judgements,
		}
		return result
SecurityEstimator.register(HashFunctionSecurityEstimator)


class PurposeEstimator(SecurityEstimator):
	_ALG_NAME = "purpose"

	@staticmethod
	def _san_name_match(san_name, fqdn):
		if san_name[0] == "*":
			return fqdn.endswith(san_name[1:])
		else:
			return san_name == fqdn

	def _judge_name(self, certificate, name):
		judgements = SecurityJudgements()
		rdns = certificate.subject.get_all(OIDDB.RDNTypes.inverse("CN"))
		have_valid_cn = False
		if len(rdns) == 0:
			judgements += SecurityJudgement(JudgementCode.Cert_Has_No_CN, "Certificate does not have any common name (CN) set.", commonness = Commonness.HIGHLY_UNUSUAL)
		else:
			for rdn in rdns:
				value = rdn.get_value(OIDDB.RDNTypes.inverse("CN"))
				if value == name:
					have_valid_cn = True
					break
			if have_valid_cn:
				if rdn.component_cnt == 1:
					judgements += SecurityJudgement(JudgementCode.Cert_CN_Match, "Common name (CN) matches '%s'." % (name), commonness = Commonness.COMMON)
				else:
					judgements += SecurityJudgement(JudgementCode.Cert_CN_Match_MultiValue_RDN, "Common name (CN) matches '%s', but is part of a multi-valued RDN." % (name), commonness = Commonness.HIGHLY_UNUSUAL)
			else:
				judgements += SecurityJudgement(JudgementCode.Cert_CN_NoMatch, "No common name (CN) matches '%s'." % (name), commonness = Commonness.UNUSUAL)

		have_valid_san = False
		extensions = certificate.get_extensions()
		extension = extensions.get_first(OIDDB.X509Extensions.inverse("SubjectAlternativeName"))
		if extension is not None:
			for san_name in extension.get_all("dNSName"):
				if self._san_name_match(san_name, name):
					have_valid_san = True
					judgements += SecurityJudgement(JudgementCode.Cert_SAN_Match, "Subject Alternative Name matches '%s'." % (name), commonness = Commonness.COMMON)
					break
			else:
				judgements += SecurityJudgement(JudgementCode.Cert_SAN_NoMatch, "No Subject Alternative Name X.509 extension matches '%s'." % (name), commonness = Commonness.UNUSUAL)
		else:
			judgements += SecurityJudgement(JudgementCode.Cert_No_SAN_Present, "No Subject Alternative Name X.509 extension present in the certificate.", commonness = Commonness.UNUSUAL)

		if (not have_valid_cn) and (not have_valid_san):
			judgements += SecurityJudgement(JudgementCode.Cert_Name_Verification_Failed, "Found neither valid common name (CN) nor valid subject alternative name (SAN).", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.NO_SECURITY)

		return judgements

	def _judge_purpose(self, certificate, purpose):
		judgements = SecurityJudgements()
		extensions = certificate.get_extensions()
		ku_ext = extensions.get_first(OIDDB.X509Extensions.inverse("KeyUsage"))
		eku_ext = extensions.get_first(OIDDB.X509Extensions.inverse("ExtendedKeyUsage"))
		ns_ext = extensions.get_first(OIDDB.X509Extensions.inverse("NetscapeCertificateType"))

		if purpose in [ AnalysisOptions.CertificatePurpose.TLSServerCertificate, AnalysisOptions.CertificatePurpose.TLSClientCertificate ]:
			if certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.Cert_Unexpectedly_CA_Cert, "Certificate is a valid CA certificate even though it's supposed to be a TLS client/server.", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.NO_SECURITY)

		if eku_ext is not None:
			if (purpose == AnalysisOptions.CertificatePurpose.TLSClientCertificate) and (not eku_ext.client_auth):
				judgements += SecurityJudgement(JudgementCode.Cert_EKU_NoClientAuth, "Certificate is supposed to be a client certificate and has an Extended Key Usage extension, but no clientAuth flag set within that extension.", commonness = Commonness.UNUSUAL)

			if (purpose == AnalysisOptions.CertificatePurpose.TLSServerCertificate) and (not eku_ext.server_auth):
				judgements += SecurityJudgement(JudgementCode.Cert_EKU_NoServerAuth, "Certificate is supposed to be a server certificate and has an Extended Key Usage extension, but no serverAuth flag set within that extension.", commonness = Commonness.UNUSUAL)

		if ns_ext is not None:
			if (purpose == AnalysisOptions.CertificatePurpose.TLSClientCertificate) and (not ns_ext.ssl_client):
				judgements += SecurityJudgement(JudgementCode.Cert_NSCT_NoSSLClient, "Certificate is supposed to be a client certificate and has an Netscape Certificate Type extension, but no sslClient flag set within that extension.", commonness = Commonness.UNUSUAL)

			if (purpose == AnalysisOptions.CertificatePurpose.TLSServerCertificate) and (not ns_ext.ssl_server):
				judgements += SecurityJudgement(JudgementCode.Cert_NSCT_NoSSLServer, "Certificate is supposed to be a server certificate and has an Netscape Certificate Type extension, but no sslServer flag set within that extension.", commonness = Commonness.UNUSUAL)

			if (purpose == AnalysisOptions.CertificatePurpose.CACertificate) and not any(flag in ns_ext.flags for flag in [ "sslCA", "emailCA", "objCA" ]):
				judgements += SecurityJudgement(JudgementCode.Cert_NSCT_NoCA, "Certificate is supposed to be a CA certificate and has an Netscape Certificate Type extension, but neither sslCA/emailCA/objCA flag set within that extension.", commonness = Commonness.UNUSUAL)

		if purpose == AnalysisOptions.CertificatePurpose.CACertificate:
			if not certificate.is_ca_certificate:
				judgements += SecurityJudgement(JudgementCode.Cert_Unexpectedly_No_CA_Cert, "Certificate is not a valid CA certificate even though it's supposed to be.", commonness = Commonness.HIGHLY_UNUSUAL, verdict = Verdict.NO_SECURITY)

		return judgements

	def analyze(self, certificate):
		result = [ ]

		if self._analysis_options.fqdn is not None:
			analysis = {
				"type":			"name_match",
				"name":			self._analysis_options.fqdn,
				"security":		self._judge_name(certificate, self._analysis_options.fqdn),
			}
			result.append(analysis)

		for purpose in self._analysis_options.purposes:
			analysis = {
				"type":			"purpose_match",
				"purpose":		purpose,
				"security":		self._judge_purpose(certificate, purpose),
			}
			result.append(analysis)

		return result
SecurityEstimator.register(PurposeEstimator)
