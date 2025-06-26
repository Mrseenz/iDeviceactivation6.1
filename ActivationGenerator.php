
<?php

declare(strict_types=1);

/**
 * Class ActivationGenerator
 *
 * Parses an iDevice activation request and generates a corresponding, cryptographically valid
 * ActivationRecord plist. This class emulates the response from Apple's activation server.
 */
class ActivationGenerator
{
    private const OPENSSL_CONFIG = ["digest_alg" => "sha256", "private_key_bits" => 2048, "private_key_type" => OPENSSL_KEYTYPE_RSA];

    /** @var array<string, mixed> Holds the device information parsed from the activation request. */
    private array $deviceInfo;

    /** @var \OpenSSLAsymmetricKey The Apple Root CA private key. */
    private \OpenSSLAsymmetricKey $rootCaKey;
    /** @var string The Apple Root CA certificate. */
    private string $rootCaCert;

    /** @var \OpenSSLAsymmetricKey The Device CA private key. */
    private \OpenSSLAsymmetricKey $deviceCaKey;
    /** @var string The Device CA certificate. */
    private string $deviceCaCert;

    /** @var \OpenSSLAsymmetricKey The server's private key for signing the AccountToken. */
    private \OpenSSLAsymmetricKey $serverPrivateKey;
    /** @var string The server's X.509 certificate (AccountTokenCertificate). */
    private string $serverCertificate;

    /** @var \OpenSSLAsymmetricKey The device's private key. */
    private \OpenSSLAsymmetricKey $devicePrivateKey;
    /** @var string The device's X.509 certificate (DeviceCertificate). */
    private string $deviceCertificate;


    /**
     * @param string $requestPlist The raw plist from the iDevice's activation request.
     * @throws \RuntimeException on cryptographic or parsing failures.
     */
    public function __construct(string $requestPlist)
    {
        $this->deviceInfo = $this->parseActivationRequest($requestPlist);

        if (empty($this->deviceInfo['SerialNumber']) || empty($this->deviceInfo['ProductType']) || empty($this->deviceInfo['UniqueDeviceID'])) {
            throw new \RuntimeException("Essential device information (SerialNumber, ProductType, UniqueDeviceID) could not be parsed from the request.");
        }

        $this->generateCaCredentials();
        $this->generateServerCredentials();
        $this->generateDeviceCredentials();
    }
    
    /**
     * Returns the parsed device information.
     */
    public function getDeviceInfo(): array
    {
        return $this->deviceInfo;
    }

    /**
     * Main public method to generate the complete ActivationRecord plist.
     */
    public function generate(): string
    {
        return $this->generateActivationRecord();
    }
    
    private function generateActivationRecord(): string
    {
        $wildcardTicket = $this->generateWildcardTicket();
        $accountTokenPayload = $this->generateAccountTokenPayload($wildcardTicket);
        $accountTokenSignature = $this->signData($accountTokenPayload, $this->serverPrivateKey);

        $components = [
            'unbrick' => true,
            'AccountTokenCertificate' => base64_encode($this->serverCertificate),
            'DeviceCertificate' => base64_encode($this->deviceCertificate),
            'RegulatoryInfo' => $this->generateRegulatoryInfo(),
            'FairPlayKeyData' => $this->generateFairPlayKeyData(),
            'AccountToken' => base64_encode($accountTokenPayload),
            'AccountTokenSignature' => $accountTokenSignature,
            'UniqueDeviceCertificate' => $this->generateUniqueDeviceCertificate(),
        ];
        
        return $this->assembleActivationRecordPlist($components);
    }

    private function parseActivationRequest(string $requestPlist): array
    {
        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($requestPlist);
        if ($xml === false || !isset($xml->dict)) {
            throw new \RuntimeException("Failed to parse activation request XML or it lacks a root dictionary.");
        }

        $deviceInfo = [];
        $dict = $xml->dict;
        $keyNodes = $dict->key;
        $valueNodes = [];

        // Collect all direct children of <dict> except for <key>
        foreach ($dict->children() as $child) {
            if ($child->getName() !== 'key') {
                $valueNodes[] = $child;
            }
        }
        
        for ($i = 0; $i < count($keyNodes); $i++) {
            $key = (string)$keyNodes[$i];
            $valueNode = $valueNodes[$i] ?? null;

            if ($valueNode === null) continue;

            // Recursively parse nested dictionaries to flatten the structure
            if ($valueNode->getName() === 'dict') {
                foreach ($valueNode->key as $subIndex => $subKeyNode) {
                    $subKey = (string)$subKeyNode;
                    $subValueNode = $valueNode->children()[$subIndex * 2 + 1];
                    $deviceInfo[$subKey] = (string)$subValueNode;
                }
            } else {
                $deviceInfo[$key] = (string)$valueNode;
            }
        }
        return $deviceInfo;
    }

    private function generateCaCredentials(): void {
        $this->rootCaKey = openssl_pkey_new(self::OPENSSL_CONFIG);
        if (!$this->rootCaKey) throw new \RuntimeException("Failed to generate Root CA private key: " . openssl_error_string());
        $dn = ["organizationName" => "Apple Inc.", "commonName" => "Apple Root CA"];
        $csr = openssl_csr_new($dn, $this->rootCaKey, self::OPENSSL_CONFIG);
        $x509 = openssl_csr_sign($csr, null, $this->rootCaKey, 3650, self::OPENSSL_CONFIG, random_int(1, PHP_INT_MAX));
        if (!$x509) throw new \RuntimeException("Failed to sign Root CA certificate: " . openssl_error_string());
        openssl_x509_export($x509, $this->rootCaCert);

        $this->deviceCaKey = openssl_pkey_new(self::OPENSSL_CONFIG);
        if (!$this->deviceCaKey) throw new \RuntimeException("Failed to generate Device CA private key: " . openssl_error_string());
        $dn = ["organizationName" => "Apple Inc.", "commonName" => "Apple Device CA"];
        $csr = openssl_csr_new($dn, $this->deviceCaKey, self::OPENSSL_CONFIG);
        $x509 = openssl_csr_sign($csr, $this->rootCaCert, $this->rootCaKey, 2000, self::OPENSSL_CONFIG, random_int(1, PHP_INT_MAX));
        if (!$x509) throw new \RuntimeException("Failed to sign Device CA certificate: " . openssl_error_string());
        openssl_x509_export($x509, $this->deviceCaCert);
    }
    
    private function generateServerCredentials(): void {
        $this->serverPrivateKey = openssl_pkey_new(self::OPENSSL_CONFIG);
        if (!$this->serverPrivateKey) throw new \RuntimeException("Failed to generate server private key: " . openssl_error_string());
        $dn = ["countryName" => "US", "stateOrProvinceName" => "California", "localityName" => "Cupertino", "organizationName" => "Apple Inc.", "commonName" => "albert.apple.com"];
        $csr = openssl_csr_new($dn, $this->serverPrivateKey, self::OPENSSL_CONFIG);
        $x509 = openssl_csr_sign($csr, $this->rootCaCert, $this->rootCaKey, 365, self::OPENSSL_CONFIG, random_int(1, PHP_INT_MAX));
        if (!$x509) throw new \RuntimeException("Failed to sign server certificate with Root CA: " . openssl_error_string());
        openssl_x509_export($x509, $this->serverCertificate);
    }
    
    private function generateDeviceCredentials(): void {
        $this->devicePrivateKey = openssl_pkey_new(self::OPENSSL_CONFIG);
        if (!$this->devicePrivateKey) throw new \RuntimeException("Failed to generate device private key: " . openssl_error_string());
        $dn = ["commonName" => $this->deviceInfo['SerialNumber'], "organizationalUnitName" => $this->deviceInfo['ProductType'], "organizationName" => "Apple Inc."];
        $csr = openssl_csr_new($dn, $this->devicePrivateKey, self::OPENSSL_CONFIG);
        $x509 = openssl_csr_sign($csr, $this->deviceCaCert, $this->deviceCaKey, 3650, self::OPENSSL_CONFIG, random_int(1, PHP_INT_MAX));
        if (!$x509) throw new \RuntimeException("Failed to sign device certificate with Device CA: " . openssl_error_string());
        openssl_x509_export($x509, $this->deviceCertificate);
    }

    private function generateWildcardTicket(): string {
        $ticketContent = json_encode([
            'UniqueDeviceID' => $this->deviceInfo['UniqueDeviceID'],
            'ActivationRandomness' => $this->deviceInfo['ActivationRandomness'] ?? null,
            'timestamp' => time(),
        ]);
        $dataFile = tempnam(sys_get_temp_dir(), 'wdt_data');
        $signedFile = tempnam(sys_get_temp_dir(), 'wdt_signed');
        if ($dataFile === false || $signedFile === false) throw new \RuntimeException("Failed to create temporary files for WildcardTicket signing.");
        try {
            file_put_contents($dataFile, $ticketContent);
            $success = openssl_pkcs7_sign($dataFile, $signedFile, $this->serverCertificate, $this->serverPrivateKey, [], PKCS7_BINARY | PKCS7_DETACHED);
            if (!$success) throw new \RuntimeException("Failed to sign WildcardTicket data: " . openssl_error_string());
            $signedData = file_get_contents($signedFile);
        } finally { @unlink($dataFile); @unlink($signedFile); }
        return base64_encode($signedData);
    }
    
    private function generateAccountTokenPayload(string $wildcardTicket): string {
        $tokenData = [
            'InternationalMobileEquipmentIdentity' => $this->deviceInfo['InternationalMobileEquipmentIdentity'] ?? '',
            'ActivationTicket' => 'MIIBkgIBATAKBggqhkjOPQQDAzGBn58/BKcA1TCfQAThQBQAn0sUYMeqwt5j6cNdU5ZeFkUyh+Fnydifh20HNWIoMpSJJp+IAAc1YigyaTIzn5c9GAAAAADu7u7u7u7u7xAAAADu7u7u7u7u75+XPgQAAAAAn5c/BAEAAACfl0AEAQAAAJ+XRgQGAAAAn5dHBAEAAACfl0gEAAAAAJ+XSQQBAAAAn5dLBAAAAACfl0wEAQAAAARnMGUCMDf5D2EOrSirzH8zQqox7r+Ih8fIaZYjFj7Q8gZChvnLmUgbX4t7sy/sKFt+p6ZnbQIxALyXlWNh9Hni+bTkmIzkfjGhw1xNZuFATlEpORJXSJAAifzq3GMirueuNaJ339NrxqN2MBAGByqGSM49AgEGBSuBBAAiA2IABA4mUWgS86Jmr2wSbV0S8OZDqo4aLqO5jzmX2AGBh9YHIlyRqitZFvB8ytw2hBwR2JjF/7sorfMjpzCciukpBenBeaiaL1TREyjLR8OuJEtUHk8ZkDE2z3emSrGQfEpIhQ==', // Static placeholder for baseband ticket
            'PhoneNumberNotificationURL' => 'https://albert.apple.com/deviceservices/phoneHome',
            'InternationalMobileSubscriberIdentity' => $this->deviceInfo['InternationalMobileSubscriberIdentity'] ?? '',
            'ProductType' => $this->deviceInfo['ProductType'],
            'UniqueDeviceID' => $this->deviceInfo['UniqueDeviceID'],
            'SerialNumber' => $this->deviceInfo['SerialNumber'],
            'MobileEquipmentIdentifier' => $this->deviceInfo['MobileEquipmentIdentifier'] ?? '',
            'InternationalMobileEquipmentIdentity2' => $this->deviceInfo['InternationalMobileEquipmentIdentity2'] ?? '',
            'PostponementInfo' => new \stdClass(),
            'ActivationRandomness' => $this->deviceInfo['ActivationRandomness'] ?? '',
            'ActivityURL' => 'https://albert.apple.com/deviceservices/activity',
            'IntegratedCircuitCardIdentity' => $this->deviceInfo['IntegratedCircuitCardIdentity'] ?? '',
            'WildcardTicket' => $wildcardTicket,
        ];

        $tokenString = "{\n";
        foreach ($tokenData as $key => $value) {
            if ($value instanceof \stdClass) {
                $tokenString .= "\t\"{$key}\" = {};\n";
            } else {
                $tokenString .= "\t\"{$key}\" = \"{$value}\";\n";
            }
        }
        $tokenString .= "}";
        return $tokenString;
    }
    
    private function signData(string $data, \OpenSSLAsymmetricKey $privateKey): string {
        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException("Failed to sign data: " . openssl_error_string());
        }
        return base64_encode($signature);
    }
    
    private function assembleActivationRecordPlist(array $components): string {
        $doc = new DOMDocument('1.0', 'UTF-8');
        $doc->standalone = true;
        $doc->formatOutput = true;
        $doctype = new DOMDocumentType('plist', '-//Apple//DTD PLIST 1.0//EN', 'http://www.apple.com/DTDs/PropertyList-1.0.dtd');
        $doc->appendChild($doctype);
        $plist = $doc->createElement('plist');
        $plist->setAttribute('version', '1.0');
        $doc->appendChild($plist);
        $rootDict = $doc->createElement('dict');
        $plist->appendChild($rootDict);
        $rootDict->appendChild($doc->createElement('key', 'ActivationRecord'));
        $activationRecordDict = $doc->createElement('dict');
        $rootDict->appendChild($activationRecordDict);
        foreach ($components as $key => $value) {
            $activationRecordDict->appendChild($doc->createElement('key', $key));
            if (is_bool($value)) {
                $activationRecordDict->appendChild($doc->createElement($value ? 'true' : 'false'));
            } else {
                $activationRecordDict->appendChild($doc->createElement('data', (string)$value));
            }
        }
        $xml = $doc->saveXML();
        if ($xml === false) throw new \RuntimeException("Failed to save final XML plist.");
        return $xml;
    }
    
    private function generateRegulatoryInfo(): string { return base64_encode(json_encode(['elabel' => ['bis' => ['regulatory' => 'R-41094897']]])); }
    private function generateFairPlayKeyData(): string { return 'LS0tLS1CRUdJTiBDT05UQUlORVItLS0tLQpBQUVBQVQzOGVycGgzbW9HSGlITlFTMU5YcTA1QjFzNUQ2UldvTHhRYWpKODVDWEZLUldvMUI2c29Pd1kzRHUyClJtdWtIemlLOFV5aFhGV1N1OCtXNVI4dEJtM3MrQ2theGpUN2hnQVJ5S0o0U253eE4vU3U2aW9ZeDE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1TTg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzw1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks0S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aWaZUJOREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlxeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg=='; }
    private function generateUniqueDeviceCertificate(): string { return 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURqRENDQXpLZ0F3SUJBZ0lHQVpBUVloQWZNQW9HQ0NxR1NNNDlCQU1DTUVVeEV6QVJCZ05WQkFnTUNrTmgKYkdsbWIzSnVhV0V4RXpBUkJnTlZCQW9NQ2tGd2NHeGxJRWx1WXk0eEdUQVhCZ05WQkFNTUVFWkVVa1JETFZWRApVbFF0VTFWQ1EwRXdIaGNOTWpRd05qRXpNRFkwTmpJd1doY05NalF3TmpJd01EWTFOakl3V2pCdU1STXdFUVlEClZRUUlEQXBEWVd4cFptOXlibWxoTVJNd0VRWURWUVFLREFwQmNIQnNaU0JKYm1NdU1SNHdIQVlEVlFRTERCVjEKWTNKMElFeGxZV1lnUTJWeWRHbG1hV05oZEdVeElqQWdCZ05WQkFNTUdUQXdNREE0TURFd0xUQXdNVGcwT1VVMApNREEyUVRRek1qWXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU2xaeVJycFRTMEZWWGphYWdoCnJlMTh2RFJPd1ZEUEZMeC9CNzE2aXhqamZyaVMvcmhrN0xtOENHSXJmWWxlOTBobUV0YUdCSlBVOFM0UUhGRmgKL0d2U280SUI0ekNDQWQ4d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0JQQXdnZ0ZNQmdrcQpoa2lHOTJOa0NnRUVnZ0U5TVlJQk9mK0VrcjJrUkFzd0NSWUVRazlTUkFJQkRQK0VtcUdTVUEwd0N4WUVRMGhKClVBSURBSUFRLzRTcWpaSkVFVEFQRmdSRlEwbEVBZ2NZU2VRQWFrTW0vNGFUdGNKakd6QVpGZ1JpYldGakJCRmoKTURwa01Eb3hNanBpTlRveVlqbzROLytHeTdYS2FSa3dGeFlFYVcxbGFRUVBNelUxTXpJME1EZzNPREkyTkRJeAovNGVieWR4dEZqQVVGZ1J6Y201dEJBeEdORWRVUjFsS1draEhOMGIvaDZ1UjBtUXlNREFXQkhWa2FXUUVLREJoCk5EWXpNRFZqWVRKbFl6Z3daamszWmpJNFlUSXlZamRpT1RjM1l6UTFZVEF4WXpneU9ISC9oN3Uxd21NYk1Ca1cKQkhkdFlXTUVFV013T21Rd09qRXlPbUkxT2pKaU9qZzIvNGVibGRKa09qQTRGZ1J6Wldsa0JEQXdOREk0TWtaRgpNelEyTTBVNE1EQXhOak15TURFeU56WXlNamt6T1RrNU56WkRRVVpHTkRrME5USTNSRVUyTVRFd01nWUtLb1pJCmh2ZGpaQVlCRHdRa01TTC9oT3FGbkZBS01BZ1dCRTFCVGxBeEFQK0Urb21VVUFvd0NCWUVUMEpLVURFQU1CSUcKQ1NxR1NJYjNZMlFLQWdRRk1BTUNBUUF3SndZSktvWklodmRqWkFnSEJBbE1MU2w5aG9ZeTE3dVFld0IKZ1pqc2hZeitkemlXU2I4U2tRQzdFZEZZM0Z2bWswQXE3ZlVnY3JhcTZqU1g4MUZWcXc1bjNpRlQwc0NRSXhibgpBQkVCQ1JZazlodFlML3RlZ0kzc29DeUZzcmM1Tjg1OXhTcHRGNFh2ejU1UVZDQkw1OFdtSzZnVFNjVHlVSDN3CjJSVERXUjNGRnJxR2Y3aTVCV1lxRVdLMEkzNFgyTWJsZnR4OTM3bmI3SysrTFVkYk81YnFZaDM0bTREcUZwbCsKZkRnaDVtdU1DNkVlWWZPeTlpdEJsbE5ad2VlUWJBUmtKa2FHUGJ5aEdpYlNCcTZzR0NrQVJ2WTltT2ZNT3hZYgplWitlNnhBRmZ4MjFwUk9BM0xZc0FmMzBycmtRc0tKODVBRHZVMzFKdUFibnpmeGQzRnorbHBXRi9FeHU5QVNtCm1XcFFTY1VZaXF5TXZHUWQ5Rnl6ZEtNYk1SQ1ExSWpGZVhOUWhWQTY0VzY4M0czbldzRjR3a3lFRHl5RnI1N2QKcUJ3dFA4djRhSXh4ZHVSODVaT0lScWs0UGlnVlUvbVRpVUVQem16Wlh2MVB3ZzNlOGpjL3pZODZoYWZHaDZsZApMbHAyTU9uakNuN1pmKzFFN0RpcTNrS280bVo0MHY0cEJOV1BodnZGZ0R5WDdSLy9UaTBvbCtnbzc1QmR2b1NpCmljckUzYUdOc0hhb0d6cE90SHVOdW5HNTh3UW9BWXMwSUhQOGNvdmxPMDhHWHVRUlh1NVYyM1VyK2ZLQ2t5dm8KSEptYWVmL29ZbmR3QzAvK1pUL2FOeTZKUUEzUzg1Y3dzaFE3YXpYajlZazNndzkzcE0xN3I5dExGejNHWDRQegoyZWhMclVOTCtZcSs1bW1zeTF6c2RlcENGMldkR09KbThnajluMjdHUDNVVnhUOVA4TkI0K1YwNzlEWXd6TEdiCjhLdGZCRExSM2cwSXppYkZQNzZ5VC9FTDUwYmlacU41SlNLYnoxS2lZSGlGS05CYnJEbDlhWWFNdnFJNHhOblgKNVdpZk43WDk3UHE0TFQzYW5rcmhUZUVqeXFxeC9kYmovMGh6bG1RRCtMaW5UV29SU2ZFVWI2Ni9peHFFb3BrbQp3V2h6dXZPMUVPaTRseUJUV09MdmxUY1h1WUpwTUpRZHNCb0dkSVdrbm80Qnp5N3BESXMvSXpNUVEzaUpEYVc3CnBiTldrSUNTdytEVWJPdDVXZFZqN0FHTEFUR2FVRW1ZS1dZNnByclo2bks4S1lReFJDN3NvdDc2SHJaajJlVnoKRVl4cm1hVy9lRHhuYVhDOGxCNXpCS0wrQ1pDVmZhWHlEdmV1MGQvdzhpNGNnRTVqSkF6S2FFcmtDeUlaSm5KdApYTkJhOEl3M3Y3aWGNlhPREFEaU9KK3hGTjdJQXlzem5YMEw4RFJ6Mkc1d2I5clllMW03eDRHM3duaklxZG1hCm9DdzZINnNPcFFRM2RWcVd0UDhrL1FJbk5ONnV2dVhEN3kvblVsdlVqcnlVbENlcFlzeDhkOFNScWw1M3d0SGwKYWxabUpvRWh0QTdRVDBUZHVVUmJ6M2dabWVXKzJRM3BlazVHaVBKRStkci83YklHRGxhdWZJVkVQTXc4clg3agpVNTVRWmZ6MHZyc3p5eGg3U0x1SDc3RmVGd3ljVlJId0t6NkFndlpOb0R2b0dMWk9KTi82V1NxVlhmczYxUEdPCmN0d29WVkkzejhYMGtWUXRHeUpjQTlFYjN0SFBHMzMrM1RpYnBsL2R0VW1LRU5WeUUrQTJUZDN5RFRydVBFQmsKZHJhM3pFc25ZWXFxR2I3aVhvMVB6Y3crUGo5QTRpQlE2cTl3RGtBbEFDdTZsZnUwCi0tLS0tRU5EIENPTlRBSU5FUi0tLS0tCg=='; }
}
