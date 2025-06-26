using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq; // For Plist parsing and generation
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs; // For SignedCms
using Newtonsoft.Json; // For JSON operations, e.g. RegulatoryInfo. NuGet: Newtonsoft.Json
// using System.Globalization; // Not directly used, can be removed if no specific culture formatting needed

namespace ActivationLogicLib
{
    public class ActivationGeneratorException : Exception
    {
        public ActivationGeneratorException(string message) : base(message) { }
        public ActivationGeneratorException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class ActivationGenerator
    {
        private Dictionary<string, string> _deviceInfo;

        private RSA _rootCaKey;
        private X509Certificate2 _rootCaCert;
        private RSA _deviceCaKey;
        private X509Certificate2 _deviceCaCert;
        private RSA _serverPrivateKey;
        private X509Certificate2 _serverCertificate;
        private RSA _devicePrivateKey;
        private X509Certificate2 _deviceCertificate;

        private const int RsaKeySizeBits = 2048;
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();


        public ActivationGenerator(byte[] requestPlistBytes)
        {
            if (requestPlistBytes == null || requestPlistBytes.Length == 0)
                throw new ArgumentNullException(nameof(requestPlistBytes), "Request Plist bytes cannot be null or empty.");

            try
            {
                _deviceInfo = ParseActivationRequest(requestPlistBytes);

                if (!_deviceInfo.ContainsKey("SerialNumber") || string.IsNullOrEmpty(_deviceInfo["SerialNumber"]) ||
                    !_deviceInfo.ContainsKey("ProductType") || string.IsNullOrEmpty(_deviceInfo["ProductType"]) ||
                    !_deviceInfo.ContainsKey("UniqueDeviceID") || string.IsNullOrEmpty(_deviceInfo["UniqueDeviceID"]))
                {
                    throw new ActivationGeneratorException("Essential device information (SerialNumber, ProductType, UniqueDeviceID) could not be parsed or is empty.");
                }

                GenerateCaCredentials();
                GenerateServerCredentials();
                GenerateDeviceCredentials();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ActivationGenerator] Constructor Error: {ex.GetType().Name} - {ex.Message}{Environment.NewLine}Trace: {ex.StackTrace}");
                throw new ActivationGeneratorException($"Failed to initialize ActivationGenerator: {ex.Message}", ex);
            }
        }

        public Dictionary<string, string> GetDeviceInfo() => new Dictionary<string, string>(_deviceInfo);

        private Dictionary<string, string> ParseActivationRequest(byte[] requestPlistBytes)
        {
            var info = new Dictionary<string, string>();
            try
            {
                XDocument plistDoc;
                using (var stream = new MemoryStream(requestPlistBytes))
                {
                    // Apple Plists might not have XML declaration, XDocument.Load is fine.
                    plistDoc = XDocument.Load(stream, LoadOptions.None);
                }

                XElement dictElement = plistDoc.Root?.Element("dict");
                if (dictElement == null) throw new ActivationGeneratorException("Plist root dictionary not found.");

                var elements = dictElement.Elements().ToList();
                for (int i = 0; i < elements.Count; i++)
                {
                    if (elements[i].Name != "key") continue;
                    string key = elements[i].Value;
                    if (i + 1 < elements.Count)
                    {
                        XElement valueNode = elements[i + 1];
                        if (valueNode.Name == "dict") // Flatten one level, as in original PHP
                        {
                            var subElements = valueNode.Elements().ToList();
                            for (int j = 0; j < subElements.Count; j++)
                            {
                                if (subElements[j].Name != "key") continue;
                                if (j + 1 < subElements.Count)
                                {
                                    info[subElements[j].Value] = subElements[j + 1].Value;
                                    j++;
                                }
                            }
                        }
                        else if (valueNode.Name == "true") info[key] = "1"; // Match Python/PHP string bool
                        else if (valueNode.Name == "false") info[key] = "";
                        else info[key] = valueNode.Value; // Includes <string>, <integer>, etc.
                        i++;
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ActivationGeneratorException($"Failed to parse activation request Plist: {ex.Message}", ex);
            }
            return info;
        }

        private static byte[] GenerateX509SerialNumber()
        {
            byte[] serialNumber = new byte[16];
            _rng.GetBytes(serialNumber);
            serialNumber[0] = (byte)(serialNumber[0] & 0x7F); // Ensure positive for BigInteger if used elsewhere
            return serialNumber;
        }

        private X509Certificate2 CreateCertificate(string subjectCommonName, string subjectOrganization, string subjectOrganizationalUnit,
                                                 int validityDays, RSA subjectKey,
                                                 X509Certificate2 issuerCertificate, RSA issuerSigningKey,
                                                 bool isCa)
        {
            var subjectNameBuilder = new StringBuilder($"CN={subjectCommonName}, O={subjectOrganization}");
            if (!string.IsNullOrEmpty(subjectOrganizationalUnit))
            {
                subjectNameBuilder.Append($", OU={subjectOrganizationalUnit}");
            }
            // For server cert, more fields might be needed if replicating Apple's cert more closely
            if (!isCa && subjectCommonName == "albert.apple.com") {
                 subjectNameBuilder.Append($", L=Cupertino, ST=California, C=US"); // ST for stateOrProvinceName
            }

            var subjectName = new X500DistinguishedName(subjectNameBuilder.ToString());
            var request = new CertificateRequest(subjectName, subjectKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, isCa, 0, true));

            X509KeyUsageFlags usageFlags = X509KeyUsageFlags.DigitalSignature; // Common for all
            if (isCa) {
                usageFlags |= X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;
            } else { // End-entity
                usageFlags |= X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment;
            }
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usageFlags, true));

            // Subject Key Identifier
            byte[] subjectPublicKeyBytes = subjectKey.ExportSubjectPublicKeyInfo();
            var skiBuilder = new SubjectAlternativeNameBuilder(); // Misusing SAN builder just to get a hash easily for SKI from public key bytes
            skiBuilder.AddDnsName("temp"); // dummy value, we only want the hash of key
            var tempSki = new X509SubjectKeyIdentifierExtension(subjectPublicKeyBytes, X509SubjectKeyIdentifierHashAlgorithm.Sha1, false); // Sha1 is common for SKI
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(tempSki.SubjectKeyIdentifierBytes, false));


            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            DateTimeOffset notAfter = notBefore.AddDays(validityDays);
            byte[] serialNumber = GenerateX509SerialNumber();

            X509Certificate2 cert;
            X500DistinguishedName finalIssuerName = (issuerCertificate != null) ? issuerCertificate.SubjectName : subjectName;
            RSA finalIssuerKey = (issuerSigningKey != null) ? issuerSigningKey : subjectKey; // Self-signing key if issuer is null

            if (issuerCertificate != null) { // Add AKI if not self-signed
                 var issuerSkiExt = issuerCertificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
                 if (issuerSkiExt != null) {
                    request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(issuerSkiExt.SubjectKeyIdentifierBytes));
                 } else { // Fallback if issuer SKI not found (less ideal)
                    request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromIssuerNameAndSerialNumber(issuerCertificate.IssuerName, issuerCertificate.GetSerialNumber()));
                 }
            }

            cert = request.Create(finalIssuerName, X509SignatureGenerator.CreateForRSA(finalIssuerKey, RSASignaturePadding.Pkcs1), notBefore, notAfter, serialNumber);

            // For operations requiring the private key with the certificate (like CmsSigner), associate it.
            // This returns a new X509Certificate2 instance.
            return cert.CopyWithPrivateKey(subjectKey);
        }

        private void GenerateCaCredentials()
        {
            _rootCaKey = RSA.Create(RsaKeySizeBits);
            _rootCaCert = CreateCertificate("Apple Root CA", "Apple Inc.", null, 3650, _rootCaKey, null, null, true);

            _deviceCaKey = RSA.Create(RsaKeySizeBits);
            _deviceCaCert = CreateCertificate("Apple Device CA", "Apple Inc.", null, 2000, _deviceCaKey, _rootCaCert, _rootCaKey, true);
        }

        private void GenerateServerCredentials()
        {
            _serverPrivateKey = RSA.Create(RsaKeySizeBits);
            // DN for server cert is more specific, handled in CreateCertificate
            _serverCertificate = CreateCertificate("albert.apple.com", "Apple Inc.", null, 365, _serverPrivateKey, _rootCaCert, _rootCaKey, false);
        }

        private void GenerateDeviceCredentials()
        {
            _devicePrivateKey = RSA.Create(RsaKeySizeBits);
            _deviceCertificate = CreateCertificate(
                _deviceInfo["SerialNumber"], "Apple Inc.", _deviceInfo["ProductType"],
                3650, _devicePrivateKey, _deviceCaCert, _deviceCaKey, false);
        }

        private byte[] SignDataPkcs7Detached(byte[] dataToSign, X509Certificate2 signingCertificateWithKey)
        {
            ContentInfo contentInfo = new ContentInfo(dataToSign);
            SignedCms signedCms = new SignedCms(contentInfo, true); // Detached

            CmsSigner cmsSigner = new CmsSigner(signingCertificateWithKey);
            cmsSigner.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"); // SHA256 OID
            // Include a list of certificates in the PKCS#7 message (chain) if needed by recipient
            // cmsSigner.IncludeOption = X509IncludeOption.Chain; // Or .EndCertOnly
            // signedCms.Certificates.Add(...) can also be used.
            // For simple detached signature, often only signer's cert is included by default.

            signedCms.ComputeSignature(cmsSigner);
            return signedCms.Encode();
        }

        private string GenerateWildcardTicket()
        {
            var ticketContentDict = new Dictionary<string, object>
            {
                { "UniqueDeviceID", _deviceInfo["UniqueDeviceID"] },
                { "ActivationRandomness", _deviceInfo.TryGetValue("ActivationRandomness", out var ar) ? ar : null },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };
            string ticketContentJson = JsonConvert.SerializeObject(ticketContentDict);
            byte[] ticketContentJsonBytes = Encoding.UTF8.GetBytes(ticketContentJson);

            // _serverCertificate should have its private key associated from CreateCertificate
            byte[] signedPkcs7Der = SignDataPkcs7Detached(ticketContentJsonBytes, _serverCertificate);
            return Convert.ToBase64String(signedPkcs7Der);
        }

        private string GenerateAccountTokenPayload(string wildcardTicketB64Str)
        {
            var tokenData = new Dictionary<string, object>
            {
                {"InternationalMobileEquipmentIdentity", _deviceInfo.TryGetValue("InternationalMobileEquipmentIdentity", out var imei) ? imei : ""},
                {"ActivationTicket", "MIIBkgIBATAKBggqhkjOPQQDAzGBn58/BKcA1TCfQAThQBQAn0sUYMeqwt5j6cNdU5ZeFkUyh+Fnydifh20HNWIoMpSJJp+IAAc1YigyaTIzn5c9GAAAAADu7u7u7u7u7xAAAADu7u7u7u7u75+XPgQAAAAAn5c/BAEAAACfl0AEAQAAAJ+XRgQGAAAAn5dHBAEAAACfl0gEAAAAAJ+XSQQBAAAAn5dLBAAAAACfl0wEAQAAAARnMGUCMDf5D2EOrSirzH8zQqox7r+Ih8fIaZYjFj7Q8gZChvnLmUgbX4t7sy/sKFt+p6ZnbQIxALyXlWNh9Hni+bTkmIzkfjGhw1xNZuFATlEpORJXSJAAifzq3GMirueuNaJ339NrxqN2MBAGByqGSM49AgEGBSuBBAAiA2IABA4mUWgS86Jmr2wSbV0S8OZDqo4aLqO5jzmX2AGBh9YHIlyRqitZFvB8ytw2hBwR2JjF/7sorfMjpzCciukpBenBeaiaL1TREyjLR8OuJEtUHk8ZkDE2z3emSrGQfEpIhQ=="},
                {"PhoneNumberNotificationURL", "https://albert.apple.com/deviceservices/phoneHome"},
                {"InternationalMobileSubscriberIdentity", _deviceInfo.TryGetValue("InternationalMobileSubscriberIdentity", out var imsi) ? imsi : ""},
                {"ProductType", _deviceInfo["ProductType"]},
                {"UniqueDeviceID", _deviceInfo["UniqueDeviceID"]},
                {"SerialNumber", _deviceInfo["SerialNumber"]},
                {"MobileEquipmentIdentifier", _deviceInfo.TryGetValue("MobileEquipmentIdentifier", out var mei) ? mei : ""},
                {"InternationalMobileEquipmentIdentity2", _deviceInfo.TryGetValue("InternationalMobileEquipmentIdentity2", out var imei2) ? imei2 : ""},
                {"PostponementInfo", new Dictionary<string,string>()},
                {"ActivationRandomness", _deviceInfo.TryGetValue("ActivationRandomness", out var ar2) ? ar2 : ""},
                {"ActivityURL", "https://albert.apple.com/deviceservices/activity"},
                {"IntegratedCircuitCardIdentity", _deviceInfo.TryGetValue("IntegratedCircuitCardIdentity", out var iccid) ? iccid : ""},
                {"WildcardTicket", wildcardTicketB64Str}
            };

            var sb = new StringBuilder("{\n");
            foreach (var kvp in tokenData)
            {
                if (kvp.Value is IDictionary<string,string> dictVal && !dictVal.Any())
                {
                    sb.AppendLine($"\t\"{kvp.Key}\" = {{}};");
                }
                else
                {
                    string valStr = (kvp.Value ?? "").ToString();
                    sb.AppendLine($"\t\"{kvp.Key}\" = \"{valStr.Replace("\"", "\\\"")}\";");
                }
            }
            sb.Append("}");
            return sb.ToString();
        }

        private string SignDataRsaSha256(string dataStr, RSA privateKey)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(dataStr);
            byte[] signatureBytes = privateKey.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signatureBytes);
        }

        private byte[] AssembleActivationRecordPlist(Dictionary<string, object> components)
        {
            // This method constructs an XML Plist where <data> elements contain *already base64 encoded strings*
            // This matches the observed output of the original PHP script.
            var activationRecordDictContent = new List<XObject>();
            foreach (var kvp in components)
            {
                activationRecordDictContent.Add(new XElement("key", kvp.Key));
                if (kvp.Value is bool bVal)
                {
                    activationRecordDictContent.Add(new XElement(bVal ? "true" : "false"));
                }
                else
                {
                    // All other values are expected to be strings (some already base64)
                    // and will be placed as the text content of a <data> tag.
                    activationRecordDictContent.Add(new XElement("data", kvp.Value.ToString()));
                }
            }
            var activationRecordDict = new XElement("dict", activationRecordDictContent.ToArray());

            var rootDict = new XElement("dict",
                new XElement("key", "ActivationRecord"),
                activationRecordDict
            );

            var plistDoc = new XDocument(
                new XDocumentType("plist", "-//Apple//DTD PLIST 1.0//EN", "http://www.apple.com/DTDs/PropertyList-1.0.dtd", null),
                new XElement("plist", new XAttribute("version", "1.0"), rootDict)
            );

            // Output XML string. Using StringWriter for specific encoding and formatting.
            // Apple plists are typically UTF-8 and indented.
            var sw = new StringWriter();
            var xtw = new System.Xml.XmlTextWriter(sw) { Formatting = System.Xml.Formatting.Indented, Indentation = 1, IndentChar = '\t' };
            plistDoc.WriteTo(xtw);
            xtw.Flush();
            return Encoding.UTF8.GetBytes(sw.ToString());
        }

        private string GenerateRegulatoryInfo() {
            var data = new { elabel = new { bis = new { regulatory = "R-41094897" } } };
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(data)));
        }

        private string GenerateFairPlayKeyData() {
            // Corrected padding: 2124 chars, ends "Cg="
            return "LS0tLS1CRUdJTiBDT05UQUlORVItLS0tLQpBQUVBQVQzOGVycGgzbW9HSGlITlFTMU5YcTA1QjFzNUQ2UldvTHhRYWpKODVDWEZLUldvMUI2c29Pd1kzRHUyClJtdWtIemlLOFV5aFhGV1N1OCtXNVI4dEJtM3MrQ2theGpUN2hnQVJ5S0o0U253eE4vU3U2aW9ZeDE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1TTg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzw1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks0S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aWaZUJOREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlxeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg==";
        }
        private string GenerateUniqueDeviceCertificate() {
            return "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURqRENDQXpLZ0F3SUJBZ0lHQVpBUVloQWZNQW9HQ0NxR1NNNDlCQU1DTUVVeEV6QVJCZ05WQkFnTUNrTmgKYkdsbWIzSnVhV0V4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEdUQVhCZ05WQkFNTUVFWkVVa1JETFZWRApVbFF0VTFWQ1EwRXdIaGNOTWpRd05qRXpNRFkwTmpJd1doY05NalF3TmpJd01EWTFOakl3V2pCdU1STXdFUVlEClZRUUlEQXBEWVd4cFptOXlibWxoTVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1SNHdIQVlEVlFRTERCVjEKWTNKMElFeGxZV1lnUTJWeWRHbG1hV05oZEdVeElqQWdCZ05WQkFNTUdUQXdNREE0TURFd0xUQXdNVGcwT1VVMApNREEyUVRRek1qWXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU2xaeVJycFRTMEZWWGphYWdoCnJlMTh2RFJPd1ZEUEZMeC9CNzE2aXhqamZyaVMvcmhrN0xtOENHSXJmWWxlOTBobUV0YUdCSlBVOFM0UUhGRmgKL0d2U280SUI0ekNDQWQ4d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0JQQXdnZ0ZNQmdrcQpoa2lHOTJOa0NnRUVnZ0U5TVlJQk9mK0VrcjJrUkFzd0NSWUVRazlTUkFJQkRQK0VtcUdTVUEwd0N4WUVRMGhKClVBSURBSUFRLzRTcWpaSkVFVEFQRmdSRlEwbEVBZ2NZU2VRQWFrTW0vNGFUdGNKakd6QVpGZ1JpYldGakJCRmoKTURwa01Eb3hNanBpTlRveVlqbzROLytHeTdYS2FSa3dGeFlFYVcxbGFRUVBNelUxTXpJME1EZzNPREkyTkRJeAovNGVieWR4dEZqQVVGZ1J6Y201dEJBeEdORWRVUjFsS1draEhOMGIvaDZ1UjBtUXlNREFXQkhWa2FXUUVLREJoCk5EWXpNRFZqWVRKbFl6Z3daamszWmpJNFlUSXlZamRpT1RjM1l6UTFZVEF4WXpneU9ISC9oN3Uxd21NYk1Ca1cKQkhkdFlXTUVFV013T21Rd09qRXlPbUkxT2pKaU9qZzIvNGVibGRKa09qQTRGZ1J6Wldsa0JEQXdOREk0TWtaRgpNelEyTTBVNE1EQXhOak15TURFeU56WXlNamt6T1RrNU56WkRRVVpHTkRrME5USTNSRVUyTVRFd01nWUtLb1pJCmh2ZGpaQVlCRHdRa01TTC9oT3FGbkZBS01BZ1dCRTFCVGxBeEFQK0Urb21VVUFvd0NCWUVUMEpLVURFQU1CSUcKQ1NxR1NJYjNZMlFLQWdRRk1BTUNBUUF3SndZSktvWklodmRqWkFnSEJBbE1MU2w5aG9ZeTE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1Tjg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzg1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks4S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aWGNlhPREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlzeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg==";
        }

        public byte[] GenerateActivationRecord()
        {
            string wildcardTicket = GenerateWildcardTicket();
            string accountTokenPayloadStr = GenerateAccountTokenPayload(wildcardTicket);
            string accountTokenSignature = SignDataRsaSha256(accountTokenPayloadStr, _serverPrivateKey);

            // The values for <data> tags must be strings that are already Base64 encoded.
            // XDocument.ToString() will not re-encode the content of an XElement if it's already a string.
            var finalComponents = new Dictionary<string, object>
            {
                { "unbrick", true },
                { "AccountTokenCertificate", Convert.ToBase64String(_serverCertificate.Export(X509ContentType.Cert)) }, // DER bytes -> B64 string
                { "DeviceCertificate", Convert.ToBase64String(_deviceCertificate.Export(X509ContentType.Cert)) },     // DER bytes -> B64 string
                { "RegulatoryInfo", GenerateRegulatoryInfo() }, // This method returns B64 string
                { "FairPlayKeyData", GenerateFairPlayKeyData() }, // This method returns B64 string
                { "AccountToken", Convert.ToBase64String(Encoding.UTF8.GetBytes(accountTokenPayloadStr)) }, // Text -> Bytes -> B64 string
                { "AccountTokenSignature", accountTokenSignature }, // This method returns B64 string
                { "UniqueDeviceCertificate", GenerateUniqueDeviceCertificate() } // This method returns B64 string
            };
            return AssembleActivationRecordPlist(finalComponents);
        }
    }
}
