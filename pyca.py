from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import secrets
import getpass
import datetime
import uuid

class pyca:
	def __init__(self, key=None, cert=None):
		self.key = key
		self.cert = cert


	def load(self, key_path='./root_ca_key.pem', cert_path='./root_ca.pem', password=None):
		if password is None:
			password = getpass.getpass('Enter private key password: ')
		with open(key_path, 'rb') as file:
			self.key = serialization.load_pem_private_key(
				file.read(),
				password.encode('utf-8'),
				default_backend()
			)
		with open(cert_path, 'rb') as file:
			self.cert = x509.load_pem_x509_certificate(file.read(), default_backend())


	def save(self, path='./', password_length=32, password=None):
		if password is None:
			password = secrets.token_urlsafe(password_length)
		with open(path + 'root_ca.pem', 'wb') as file:
			file.write(self.cert.public_bytes(serialization.Encoding.PEM))
		with open(path + 'root_ca_key.pem', 'wb') as file:
			file.write(self.key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
			))
		print("The key and certificate have been saved to: " + path)
		return password


	def generate(self, country_name=u"XX", state=u"Undefined",locality=u"Undefined",
				organization=u"Undefined", common_name=u"Undefined", dns_name=u"localhost", validity=365):
		self.key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)
		subject = issuer = x509.Name([
			x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
			x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
			x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
			x509.NameAttribute(NameOID.COMMON_NAME, common_name),
		])
		self.cert = x509.CertificateBuilder().subject_name(
			subject
		).issuer_name(
			issuer
		).public_key(
			self.key.public_key()
		).serial_number(
			x509.random_serial_number()
		).not_valid_before(
			datetime.datetime.utcnow()
		).not_valid_after(
			datetime.datetime.utcnow() + datetime.timedelta(days=validity)
		).add_extension(
			x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
			critical=False,
		).add_extension(
			extension=x509.BasicConstraints(ca=True, path_length=3),
			critical=True
		).sign(self.key, hashes.SHA256(), default_backend())


	def reset(self):
		self.key = ""
		self.cert = ""
		print("The key and certificate have been overwritten")
		
		
	def sign_csr(self, csr_path='./csr.pem', cert_path='./', server=False):
		serial_id = uuid.uuid4().int
		with open(csr_path, "rb") as file:
			csr = x509.load_pem_x509_csr(file.read(), default_backend())
		crt_tmp = x509.CertificateBuilder().subject_name(
			csr.subject
		).issuer_name(
			self.cert.subject
		).public_key(
			csr.public_key()
		).serial_number(
			serial_id
		).not_valid_before(
			datetime.datetime.utcnow()
		).not_valid_after(
			datetime.datetime.utcnow() + datetime.timedelta(days=365)
		).add_extension(
			extension=x509.KeyUsage(
				digital_signature=True, key_encipherment=True, content_commitment=True,
				data_encipherment=False, key_agreement=False, encipher_only=False, 
				decipher_only=False, key_cert_sign=False, crl_sign=False,
			),
			critical=True
		).add_extension(
			extension=x509.BasicConstraints(ca=False, path_length=None),
			critical=True
		).add_extension(
			extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
			critical=False
		)
		if server is True:
			crt = crt_tmp.add_extension(
				x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
			).sign(
				private_key=self.key,
				algorithm=hashes.SHA256(),
				backend=default_backend()
			)
		else:
			crt = crt_tmp.add_extension(
				x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
			).sign(
				private_key=self.key,
				algorithm=hashes.SHA256(),
				backend=default_backend()
			)
		with open(cert_path + 'csr.pem', "wb") as file:
			file.write(crt.public_bytes(serialization.Encoding.PEM))
		print("Generated certificate can be found at: ")
		return serial_id


	def generate_csr(self, path='./',country_name=u"XX", state=u"Undefined", locality=u"Undefined", 
					organization=u"Undefined", common_name=u"Undefined", validity=365, password=None):
		if password is None:
			password = secrets.token_urlsafe(password_length)
		key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)
		with open(path + "csr_key.pem", "wb") as file:
			file.write(key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')),
		))
		csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
				x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
				x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
				x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
				x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
				x509.NameAttribute(NameOID.COMMON_NAME, common_name),
			])
			).sign(key, hashes.SHA256(), default_backend())
		with open(path + "csr.pem", "wb") as file:
			file.write(csr.public_bytes(serialization.Encoding.PEM))
		print("The key and certificate have been saved to: " + path)
		return password
