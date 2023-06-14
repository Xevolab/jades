/*
 * Author    : Francesco
 * Created at: 2023-06-02 16:25
 * Edited by : Francesco
 * Edited at : 2023-06-13 17:44
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { Sequence, CharacterString, Integer } from "asn1js";
import { X509Certificate } from "crypto";

/**
 * Generate a Key ID (kid) from a certificate
 *
 * `kid` must be base64 encoding of one DER-encoded instance of type IssuerSerial.
 * └-> https://www.ietf.org/rfc/rfc5035.txt
 * └-> https://www.ietf.org/rfc/rfc5280.txt
 */

export default function generateKid(cert: X509Certificate) {
	/*

	KID = base64url(derEncodeSequence(IssuerSerial))

	IssuerSerial ::= SEQUENCE {
		issuer                   GeneralNames,
		serialNumber             CertificateSerialNumber
	}

	GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

	GeneralName ::= CHOICE {
		  otherName                       [0]     OtherName,
		  rfc822Name                      [1]     IA5String,
		  dNSName                         [2]     IA5String,
		  x400Address                     [3]     ORAddress,
		  directoryName                   [4]     Name,
		  ediPartyName                    [5]     EDIPartyName,
		  uniformResourceIdentifier       [6]     IA5String,
		  iPAddress                       [7]     OCTET STRING,
		  registeredID                    [8]     OBJECT IDENTIFIER }


	CertificateSerialNumber ::= INTEGER

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
			new CharacterString({
				value: cert.issuer
			}),
			// serialNumber
			new Integer({
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
