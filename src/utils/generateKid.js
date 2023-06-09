/*
 * Author    : Francesco
 * Created at: 2023-06-02 16:25
 * Edited by : Francesco
 * Edited at : 2023-06-09 16:24
 * 
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import asn1, { Sequence } from "asn1js";

/**
 * Generate a Key ID (kid) from a certificate
 * 
 * `kid` must be base64 encoding of one DER-encoded instance of type IssuerSerial.
 * └-> https://www.ietf.org/rfc/rfc5035.txt
 */

export default function generateKid(cert) {
	/*
	
	KID = base64url(derEncodeSequence(IssuerSerial))

	IssuerSerial ::= SEQUENCE {
		issuer                   GeneralNames,
		serialNumber             CertificateSerialNumber
	}

	issuer
		contains the issuer name of the certificate.  For non-attribute
		certificates, the issuer MUST contain only the issuer name from
		the certificate encoded in the directoryName choice of
		GeneralNames.  For attribute certificates, the issuer MUST contain
		the issuer name field from the attribute certificate.

	serialNumber
		holds the serial number that uniquely identifies the certificate
		for the issuer.
	*/

	// Create an instance of the Sequence ASN.1 class
	const sequence = new Sequence({
		value: [
			// issuer
			new asn1.CharacterString({
				value: cert.issuer
			}),
			// serialNumber
			new asn1.Integer({
				// Passing the serial number as a string is not supported
				// value: cert.serialNumber,
				valueHex: new Uint8Array(Buffer.from(cert.serialNumber, "hex"))
			}),
		],
	});

	// DER-encode the sequence
	const derEncoded = sequence.toBER(false);

	// Return the base64 encoding of the DER-encoded sequence
	return Buffer.from(derEncoded).toString("base64");
}
