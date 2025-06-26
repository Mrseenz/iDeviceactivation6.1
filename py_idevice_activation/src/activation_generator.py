import base64
import datetime
import json
import plistlib
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

OPENSSL_CONFIG_DETAILS = {
    "digest_alg": hashes.SHA256(),
    "private_key_bits": 2048,
    "private_key_exponent": 65537,
}

class ActivationGeneratorException(Exception):
    pass

class ActivationGenerator:
    def __init__(self, request_plist_bytes: bytes):
        self.device_info = self._parse_activation_request(request_plist_bytes)
        if not all(k in self.device_info for k in ['SerialNumber', 'ProductType', 'UniqueDeviceID']):
            raise ActivationGeneratorException("Essential device information (SerialNumber, ProductType, UniqueDeviceID) could not be parsed.")
        self._generate_ca_credentials()
        self._generate_server_credentials()
        self._generate_device_credentials()

    def get_device_info(self) -> dict:
        return self.device_info

    def _parse_activation_request(self, request_plist_bytes: bytes) -> dict:
        try:
            if isinstance(request_plist_bytes, str):
                request_plist_bytes = request_plist_bytes.encode('utf-8')
            plist_data = plistlib.loads(request_plist_bytes)
        except plistlib.InvalidFileException as e:
            raise ActivationGeneratorException(f"Failed to parse activation request plist: {e}")

        flat_device_info = {}
        if isinstance(plist_data, dict):
            for key, value in plist_data.items():
                if isinstance(value, dict): # Flatten one level of nested dicts, as in PHP
                    for sub_key, sub_value in value.items():
                        flat_device_info[sub_key] = str(sub_value)
                else:
                    if isinstance(value, bool): # Match PHP bool to string '1' or ''
                        flat_device_info[key] = '1' if value else ''
                    elif isinstance(value, bytes):
                        try:
                            flat_device_info[key] = value.decode('utf-8')
                        except UnicodeDecodeError: # If not UTF-8, store as base64 string
                            flat_device_info[key] = base64.b64encode(value).decode('utf-8')
                    else:
                        flat_device_info[key] = str(value)
        return flat_device_info

    def _generate_key_and_cert(self, common_name_str, issuer_cert_obj=None, issuer_key_obj=None, days_valid=365, is_ca=False, org_name_str="Apple Inc.", country_str="US", state_str="California", locality_str="Cupertino", org_unit_name_str=None, serial_int=None):
        private_key = rsa.generate_private_key(
            public_exponent=OPENSSL_CONFIG_DETAILS["private_key_exponent"],
            key_size=OPENSSL_CONFIG_DETAILS["private_key_bits"],
            backend=default_backend()
        )
        subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name_str)]
        if org_name_str: subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name_str))
        if country_str and not is_ca: subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_str))
        if state_str and not is_ca: subject_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_str))
        if locality_str and not is_ca: subject_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality_str))
        if org_unit_name_str: subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit_name_str))

        subject_name = x509.Name(subject_attrs)
        builder = x509.CertificateBuilder().subject_name(subject_name)

        if issuer_cert_obj and issuer_key_obj:
            builder = builder.issuer_name(issuer_cert_obj.subject)
            signing_key = issuer_key_obj
        else: # Self-signed
            builder = builder.issuer_name(subject_name)
            signing_key = private_key

        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(serial_int if serial_int is not None else x509.random_serial_number())

        now = datetime.datetime.now(datetime.timezone.utc)
        builder = builder.not_valid_before(now - datetime.timedelta(days=1)) # Valid from yesterday
        builder = builder.not_valid_after(now + datetime.timedelta(days=days_valid))

        if is_ca:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        else: # End-entity certificate
             builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=True, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)

        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        if issuer_cert_obj: # Add AuthorityKeyIdentifier if signed by another cert
            builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert_obj.public_key()), critical=False)

        certificate_obj = builder.sign(signing_key, OPENSSL_CONFIG_DETAILS["digest_alg"], default_backend())
        certificate_pem_str = certificate_obj.public_bytes(crypto_serialization.Encoding.PEM).decode('utf-8')
        return private_key, certificate_obj, certificate_pem_str

    def _generate_ca_credentials(self):
        self.root_ca_key, self.root_ca_cert_obj, self.root_ca_cert_pem = self._generate_key_and_cert(common_name_str="Apple Root CA", days_valid=3650, is_ca=True, country_str=None, state_str=None, locality_str=None, serial_int=int.from_bytes(uuid.uuid4().bytes[:15], 'big'))
        self.device_ca_key, self.device_ca_cert_obj, self.device_ca_cert_pem = self._generate_key_and_cert(common_name_str="Apple Device CA", issuer_cert_obj=self.root_ca_cert_obj, issuer_key_obj=self.root_ca_key, days_valid=2000, is_ca=True, country_str=None, state_str=None, locality_str=None, serial_int=int.from_bytes(uuid.uuid4().bytes[:15], 'big'))

    def _generate_server_credentials(self):
        self.server_private_key, self.server_cert_obj, self.server_certificate_pem = self._generate_key_and_cert(common_name_str="albert.apple.com", issuer_cert_obj=self.root_ca_cert_obj, issuer_key_obj=self.root_ca_key, days_valid=365, serial_int=int.from_bytes(uuid.uuid4().bytes[:15], 'big'))

    def _generate_device_credentials(self):
        self.device_private_key, self.device_cert_obj, self.device_certificate_pem = self._generate_key_and_cert(common_name_str=self.device_info['SerialNumber'], org_unit_name_str=self.device_info['ProductType'], issuer_cert_obj=self.device_ca_cert_obj, issuer_key_obj=self.device_ca_key, days_valid=3650, country_str=None, state_str=None, locality_str=None, serial_int=int.from_bytes(uuid.uuid4().bytes[:15], 'big'))

    def _sign_data_pkcs7_detached(self, data_to_sign_bytes: bytes) -> bytes:
        builder = pkcs7.PKCS7SignatureBuilder().set_data(data_to_sign_bytes)
        signed_data_der = builder.add_signer(
            certificate=self.server_cert_obj, private_key=self.server_private_key, hash_algorithm=OPENSSL_CONFIG_DETAILS["digest_alg"]
        ).sign(encoding=crypto_serialization.Encoding.DER, options=[pkcs7.PKCS7Options.DetachedSignature])
        return signed_data_der

    def _generate_wildcard_ticket(self) -> str: # Returns base64 string
        ticket_content_dict = {'UniqueDeviceID': self.device_info['UniqueDeviceID'], 'ActivationRandomness': self.device_info.get('ActivationRandomness'), 'timestamp': int(datetime.datetime.now(datetime.timezone.utc).timestamp())}
        ticket_content_json_bytes = json.dumps(ticket_content_dict, sort_keys=True).encode('utf-8')
        signed_pkcs7_der = self._sign_data_pkcs7_detached(ticket_content_json_bytes)
        return base64.b64encode(signed_pkcs7_der).decode('utf-8')

    def _generate_account_token_payload(self, wildcard_ticket_b64_str: str) -> str:
        token_data = {
            'InternationalMobileEquipmentIdentity': self.device_info.get('InternationalMobileEquipmentIdentity', ''),
            'ActivationTicket': 'MIIBkgIBATAKBggqhkjOPQQDAzGBn58/BKcA1TCfQAThQBQAn0sUYMeqwt5j6cNdU5ZeFkUyh+Fnydifh20HNWIoMpSJJp+IAAc1YigyaTIzn5c9GAAAAADu7u7u7u7u7xAAAADu7u7u7u7u75+XPgQAAAAAn5c/BAEAAACfl0AEAQAAAJ+XRgQGAAAAn5dHBAEAAACfl0gEAAAAAJ+XSQQBAAAAn5dLBAAAAACfl0wEAQAAAARnMGUCMDf5D2EOrSirzH8zQqox7r+Ih8fIaZYjFj7Q8gZChvnLmUgbX4t7sy/sKFt+p6ZnbQIxALyXlWNh9Hni+bTkmIzkfjGhw1xNZuFATlEpORJXSJAAifzq3GMirueuNaJ339NrxqN2MBAGByqGSM49AgEGBSuBBAAiA2IABA4mUWgS86Jmr2wSbV0S8OZDqo4aLqO5jzmX2AGBh9YHIlyRqitZFvB8ytw2hBwR2JjF/7sorfMjpzCciukpBenBeaiaL1TREyjLR8OuJEtUHk8ZkDE2z3emSrGQfEpIhQ==',
            'PhoneNumberNotificationURL': 'https://albert.apple.com/deviceservices/phoneHome',
            'InternationalMobileSubscriberIdentity': self.device_info.get('InternationalMobileSubscriberIdentity', ''),
            'ProductType': self.device_info['ProductType'],
            'UniqueDeviceID': self.device_info['UniqueDeviceID'],
            'SerialNumber': self.device_info['SerialNumber'],
            'MobileEquipmentIdentifier': self.device_info.get('MobileEquipmentIdentifier', ''),
            'InternationalMobileEquipmentIdentity2': self.device_info.get('InternationalMobileEquipmentIdentity2', ''),
            'PostponementInfo': {},
            'ActivationRandomness': self.device_info.get('ActivationRandomness', ''),
            'ActivityURL': 'https://albert.apple.com/deviceservices/activity',
            'IntegratedCircuitCardIdentity': self.device_info.get('IntegratedCircuitCardIdentity', ''),
            'WildcardTicket': wildcard_ticket_b64_str,
        }
        token_string_parts = []
        for key, value in token_data.items():
            if isinstance(value, dict) and not value: # For PostponementInfo = {};
                token_string_parts.append(f'\t"{key}" = {{}};')
            else: # Ensure values are escaped if they contain quotes, etc.
                escaped_value = str(value).replace('\\', '\\\\').replace('"', '\\"')
                token_string_parts.append(f'\t"{key}" = "{escaped_value}";')
        return "{{\n{}\n}}".format("\n".join(token_string_parts))

    def _sign_data_rsa_sha256(self, data_str: str, private_key_obj: rsa.RSAPrivateKey) -> str: # returns base64 string
        signature_bytes = private_key_obj.sign(data_str.encode('utf-8'), padding.PKCS1v15(), OPENSSL_CONFIG_DETAILS["digest_alg"])
        return base64.b64encode(signature_bytes).decode('utf-8')

    def _assemble_activation_record_plist(self, components_dict: dict) -> bytes:
        final_plist_components = {}
        for key, value_original in components_dict.items():
            if key == 'unbrick': # Boolean
                final_plist_components[key] = value_original
            elif key in ['AccountTokenCertificate', 'DeviceCertificate', 'AccountToken']: # These are text, encode to bytes for <data>
                final_plist_components[key] = value_original.encode('utf-8')
            elif key in ['AccountTokenSignature', 'FairPlayKeyData', 'UniqueDeviceCertificate', 'RegulatoryInfo']: # These are already base64 strings, decode to raw bytes for <data>
                final_plist_components[key] = base64.b64decode(value_original)
            else: # Should not happen with current components
                final_plist_components[key] = str(value_original).encode('utf-8')

        plist_structure = {'ActivationRecord': final_plist_components}
        plist_bytes = plistlib.dumps(plist_structure, fmt=plistlib.FMT_XML, sort_keys=False)

        doctype_str = '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        xml_declaration = b'<?xml version="1.0" encoding="UTF-8"?>\n'
        current_plist_content = plist_bytes
        if current_plist_content.startswith(xml_declaration): # Remove default XML decl if present
            current_plist_content = current_plist_content[len(xml_declaration):]

        # Prepend our XML declaration and DOCTYPE
        final_xml_bytes = xml_declaration + doctype_str.encode('utf-8') + current_plist_content
        return final_xml_bytes

    def _generate_regulatory_info(self) -> str: # returns base64 string
        data = {'elabel': {'bis': {'regulatory': 'R-41094897'}}}
        return base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')

    def _generate_fair_play_key_data(self) -> str: # returns base64 string
        # IMPORTANT NOTE: This base64 string is sourced from the original PHP.
        # It was found to be problematic for Python's base64.b64decode due to padding/length.
        # The version below (2124 chars, ending "Cg=") is believed to be the correctly padded
        # version for Python's stricter decoder. The original PHP string was 2125 chars, ending "Cg==".
        # If `binascii.Error: Invalid base64-encoded string: number of data characters (2125) ...` occurs,
        # it means this string is still not being updated correctly in the execution environment,
        # or the original PHP's base64_decode was more lenient with an inherently malformed string.
        # The data part (pre-padding) should be 2123 chars. 2123 % 4 = 3, requiring one '=' pad char.
        return 'LS0tLS1CRUdJTiBDT05UQUlORVItLS0tLQpBQUVBQVQzOGVycGgzbW9HSGlITlFTMU5YcTA1QjFzNUQ2UldvTHhRYWpKODVDWEZLUldvMUI2c29Pd1kzRHUyClJtdWtIemlLOFV5aFhGV1N1OCtXNVI4dEJtM3MrQ2theGpUN2hnQVJ5S0o0U253eE4vU3U2aW9ZeDE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1TTg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzw1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks0S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aWaZUJOREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlxeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg='

    def _generate_unique_device_certificate(self) -> str: # returns base64 string
        return 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURqRENDQXpLZ0F3SUJBZ0lHQVpBUVloQWZNQW9HQ0NxR1NNNDlCQU1DTUVVeEV6QVJCZ05WQkFnTUNrTmgKYkdsbWIzSnVhV0V4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEdUQVhCZ05WQkFNTUVFWkVVa1JETFZWRApVbFF0VTFWQ1EwRXdIaGNOTWpRd05qRXpNRFkwTmpJd1doY05NalF3TmpJd01EWTFOakl3V2pCdU1STXdFUVlEClZRUUlEQXBEWVd4cFptOXlibWxoTVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1SNHdIQVlEVlFRTERCVjEKWTNKMElFeGxZV1lnUTJWeWRHbG1hV05oZEdVeElqQWdCZ05WQkFNTUdUQXdNREE0TURFd0xUQXdNVGcwT1VVMApNREEyUVRRek1qWXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU2xaeVJycFRTMEZWWGphYWdoCnJlMTh2RFJPd1ZEUEZMeC9CNzE2aXhqamZyaVMvcmhrN0xtOENHSXJmWWxlOTBobUV0YUdCSlBVOFM0UUhGRmgKL0d2U280SUI0ekNDQWQ4d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0JQQXdnZ0ZNQmdrcQpoa2lHOTJOa0NnRUVnZ0U5TVlJQk9mK0VrcjJrUkFzd0NSWUVRazlTUkFJQkRQK0VtcUdTVUEwd0N4WUVRMGhKClVBSURBSUFRLzRTcWpaSkVFVEFQRmdSRlEwbEVBZ2NZU2VRQWFrTW0vNGFUdGNKakd6QVpGZ1JpYldGakJCRmoKTURwa01Eb3hNanBpTlRveVlqbzROLytHeTdYS2FSa3dGeFlFYVcxbGFRUVBNelUxTXpJME1EZzNPREkyTkRJeAovNGVieWR4dEZqQVVGZ1J6Y201dEJBeEdORWRVUjFsS1draEhOMGIvaDZ1UjBtUXlNREFXQkhWa2FXUUVLREJoCk5EWXpNRFZqWVRKbFl6Z3daamszWmpJNFlUSXlZamRpT1RjM1l6UTFZVEF4WXpneU9ISC9oN3Uxd21NYk1Ca1cKQkhkdFlXTUVFV013T21Rd09qRXlPbUkxT2pKaU9qZzIvNGVibGRKa09qQTRGZ1J6Wldsa0JEQXdOREk0TWtaRgpNelEyTTBVNE1EQXhOak15TURFeU56WXlNamt6T1RrNU56WkRRVVpHTkRrME5USTNSRVUyTVRFd01nWUtLb1pJCmh2ZGpaQVlCRHdRa01TTC9oT3FGbkZBS01BZ1dCRTFCVGxBeEFQK0Urb21VVUFvd0NCWUVUMEpLVURFQU1CSUcKQ1NxR1NJYjNZMlFLQWdRRk1BTUNBUUF3SndZSktvWklodmRqWkFnSEJBbE1MU2w5aG9ZeTE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1Tjg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzg1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks4S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aWGNlhPREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlzeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg=='

    def generate_activation_record(self) -> bytes: # Returns final XML plist as bytes
        wildcard_ticket_b64_str = self._generate_wildcard_ticket()
        account_token_payload_str = self._generate_account_token_payload(wildcard_ticket_b64_str)
        account_token_signature_b64_str = self._sign_data_rsa_sha256(account_token_payload_str, self.server_private_key)

        components_dict = {
            'unbrick': True,
            'AccountTokenCertificate': self.server_certificate_pem,
            'DeviceCertificate': self.device_certificate_pem,
            'RegulatoryInfo': self._generate_regulatory_info(),
            'FairPlayKeyData': self._generate_fair_play_key_data(),
            'AccountToken': account_token_payload_str,
            'AccountTokenSignature': account_token_signature_b64_str,
            'UniqueDeviceCertificate': self._generate_unique_device_certificate(),
        }
        return self._assemble_activation_record_plist(components_dict)

if __name__ == '__main__':
    inner_plist_dict = {
        'SerialNumber': 'PYTHONSIMSN001',
        'ProductType': 'iPhone13,3',
        'UniqueDeviceID': 'simulatedpythonudid1234567890abcdef0123',
        'ActivationRandomness': 'pyrandomsimvalue',
        'InternationalMobileEquipmentIdentity': '012345678901234',
        'BuildVersion': '19A001',
        'ActivationInfo': {'DeviceSupportsHaptics': True, 'TelephonyCapability': True}
    }
    request_plist_bytes = plistlib.dumps(inner_plist_dict)
    print(f"--- Test Activation Request Plist (Bytes) ---\n{request_plist_bytes}\n")
    try:
        generator = ActivationGenerator(request_plist_bytes)
        print("--- Parsed Device Info ---")
        for key, value in generator.get_device_info().items(): print(f"  {key}: {value}")
        activation_record_xml_bytes = generator.generate_activation_record()
        print("\n--- Generated Activation Record XML ---")
        print(activation_record_xml_bytes.decode('utf-8'))
    except ActivationGeneratorException as e:
        print(f"ACTIVATION GENERATOR ERROR: {e}")
    except Exception as e:
        import traceback
        print(f"AN UNEXPECTED ERROR OCCURRED:")
        traceback.print_exc()
