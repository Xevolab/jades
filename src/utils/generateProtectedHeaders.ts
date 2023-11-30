/*
 * Author    : Francesco
 * Created at: 2023-06-13 21:20
 * Edited by : Francesco
 * Edited at : 2023-06-13 22:21
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

const { validateProtected } = require("../schemas/schemas");

import type { SignAlg } from "../types";
import type { ProtectedHeaders } from "../types";

interface ExtProtectedHeaders extends ProtectedHeaders {
	alg: SignAlg,
	cty: null | string,
	b64: boolean,
	"x5t#o"?: null | { digAlg: string, digVal: string },
	"x5t#S256"?: null | string,
	crit?: string[]
}

export default function generateProtectedHeaders(
	{
		kid = null,

		x5u = null,
		x5c = null,
		x5tS256 = null,
		x5tO = null,
		sigX5ts = null,

		// These properties are part of the standard but are not directly
		// checked by the library. Using the `validate` function, you can
		// check if the payload is valid or not against the official schema.
		srCms = null,
		srAts = null,
		sigPl = null,
		sigPId = null,

		sigD = null,

		sigT = (new Date().toISOString()).slice(0, -5) + "Z",
		// These properties are not yet supported by the library but could be
		// in the future.
		// Please, consider contributing to the project if you want to help.
		adoTst = null,
	}: ProtectedHeaders,
	{
		alg,
		cty,
		detached
	}: { alg: SignAlg, cty: null | string, detached: boolean }) {

	/**
	 * `kid`
	 * ETSI TS 119 182-1 - Section 5.1.4
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	 */
	if (kid !== null && typeof kid !== "string") throw new Error("Invalid kid; needs to be a string.");
	if (typeof kid === "string" && !/^[a-zA-Z0-9-_]+$/g.test(kid)) throw new Error("Invalid kid; needs to be a base64 string.");


	/**
	 * `x5u`
	 * ETSI TS 119 182-1 - Section 5.1.5
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5
	 *
	 * `x5u` must be a URI that refers to a resource for the X.509 public key certificate or
	 * certificate chain corresponding to the key used to digitally sign the JWS.
	 */
	if (x5u !== null && typeof x5u !== "string") throw new Error("Invalid x5u; needs to be a string.");
	if (x5u !== null && !/^(?:https?|ftp):\/\/[^\s/$.?#].[^\s]*$/g.test(x5u)) throw new Error("Invalid x5u; needs to be a valid URI.");
	if (x5u !== null && x5c !== null) throw new Error("Invalid x5u; needs to be null when x5c is not null.");

	/**
	 * `x5c`
	 * ETSI TS 119 182-1 - Section 5.1.8
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
	 *
	 * `x5c` must be a base64 encoded string of one or more DER-encoded X.509 certificates.
	 * The certificate chain must be ordered such that each certificate contains the public key of
	 * the subsequent certificate.
	 * The first certificate must correspond to the key used to digitally sign the JWS.
	 */
	if (x5c !== null && x5c.length === undefined) throw new Error("Invalid x5c; needs to be an array.");
	if (x5c !== null && x5c.length === 0) throw new Error("Invalid x5c; needs to be an array with at least one element.");
	if (x5c !== null && !x5c.every((t) => typeof t === "string")) throw new Error("Invalid x5c; needs to be an array of strings.");
	if (x5c !== null && !x5c.every((t) => /^[a-zA-Z0-9=/+]+$/g.test(t))) throw new Error("Invalid x5c; needs to be an array of base64 strings.");

	/**
	 * `x5t#256`
	 * ETSI TS 119 182-1 - Section 5.1.7
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8
	 *
	 * `x5t#256` must be a base64url encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding
	 * of the X.509 certificate corresponding to the key used to digitally sign the JWS.
	 */
	if (x5tS256 !== null && typeof x5tS256 !== "string") throw new Error("Invalid x5tS256; needs to be a string.");
	if (x5tS256 !== null && !/^[a-zA-Z0-9-_]+$/g.test(x5tS256)) throw new Error("Invalid x5tS256; needs to be a base64url string.");
	if (x5tS256 !== null && x5c !== null) throw new Error("Invalid x5tS256; needs to be null when x5c is not null.");

	/**
	 * `x5t#o`
	 * ETSI TS 119 182-1 - Section 5.2.2.2
	 *
	 * `x5t#o` must be an object with the following properties:
	 *  - `digAlg` must be a string containing the digest algorithm used to compute the thumbprint.
	 *  - `digVal` must be a base64url encoded thumbprint of the DER encoding of the X.509
	 * certificate corresponding to the key used to digitally sign the JWS.
	 */
	if (x5tO !== null && typeof x5tO !== "object") throw new Error("Invalid x5tO; needs to be an object.");
	if (x5tO !== null && !("digAlg" in x5tO)) throw new Error("Invalid x5tO; needs to have a property named `digAlg`.");
	if (x5tO !== null && !("digVal" in x5tO)) throw new Error("Invalid x5tO; needs to have a property named `digVal`.");
	if (x5tO !== null && typeof x5tO.digAlg !== "string") throw new Error("Invalid x5tO; `digAlg` needs to be a string.");
	if (x5tO !== null && typeof x5tO.digVal !== "string") throw new Error("Invalid x5tO; `digVal` needs to be a string.");
	if (x5tO !== null && !/^[a-zA-Z0-9-_]+$/g.test(x5tO.digVal as string)) throw new Error("Invalid x5tO; `digVal` needs to be a base64url string.");

	/**
	 * `sigX5ts`
	 * ETSI TS 119 182-1 - Section 5.2.2.3
	 *
	 * `sigX5ts` must be an array of at least 2 objects with the same properties as `x5t#o` (see
	 * above).
	 * The first object must contain the thumbprint of the certificate used to sign the JWS.
	 * Each object may contain digest values computed with the algorithm SHA-256.
	 */
	if (sigX5ts !== null && sigX5ts.length === undefined) throw new Error("Invalid sigX5ts; needs to be an array.");
	if (sigX5ts !== null && sigX5ts.length < 2) throw new Error("Invalid sigX5ts; needs to be an array with at least 2 elements.");
	if (sigX5ts !== null && !sigX5ts.every((t) => typeof t === "object")) throw new Error("Invalid sigX5ts; needs to be an array of objects.");

	// ETSI TS 119 182-1 - Section 5.1.7
	// A JAdES signature shall have at least one of the following header parameters in its JWS
	// Protected Header: x5t#S256, x5c, x5t#o, sigX5ts.
	if (x5tS256 === null && x5c === null && x5tO === null && sigX5ts === null) throw new Error("Invalid JAdES signature; needs to have at least one of the following header parameters in its JWS Protected Header: x5t#S256, x5c, x5t#o, sigX5ts.");


	/**
	 * `sigD`
	 * ETSI TS 119 182-1 - Section 5.2.8
	 *
	 * `sigD` is an object referencing one or more detached data objects, meaning that this property
	 * is only present when the JWS Payload is detached.
	 * ⚠️ The `sigD` header parameter is not checked by this library.
	 */
	if (sigD !== null && typeof sigD !== "object") throw new Error("Invalid sigD; needs to be an object.");
	if (sigD !== null && !detached) throw new Error("Invalid sigD; needs to be null when detached is false.");

	// --> Preparing for the signature

	// Creating the JOSE headers
	const JOSE: ExtProtectedHeaders = {
		alg,
		cty,
		kid,
		x5u,
		x5c,
		"x5t#S256": x5tS256,
		"x5t#o": x5tO,
		sigX5ts,

		sigD,
		sigPl,
		sigPId,
		srCms,
		srAts,

		// Timestamp related headers
		sigT,
		adoTst,

		/**
		 * `b64`
		 * ETSI TS 119 182-1 - Section 5.1.10
		 * └-> https://datatracker.ietf.org/doc/html/rfc7797#section-3
		 */
		b64: true,
	};

	// Removing all null or undefined values from the JOSE headers
	Object.keys(JOSE)
		.forEach((key) => (JOSE[key as keyof ExtProtectedHeaders] === null || JOSE[key as keyof ExtProtectedHeaders] === undefined) && delete JOSE[key as keyof ExtProtectedHeaders]);

	// Calculating the `crit` header parameter
	const critParameters = ["x5t#o", "sigX5ts", "sigT", "sigD", "sigPl", "sigPId", "srCms", "srAts", "adoTst", "b64"];
	JOSE.crit = critParameters.filter((parameter) => parameter in JOSE);

	// --> Checking against the schema

	// Checking the JOSE headers against the schema
	const validationResult = validateProtected(JOSE);
	if (!validationResult)
		throw new Error(`Invalid JOSE headers; \n-> ${validateProtected.errors.map((error: Error, i: number) => `${i}: ${error.message}`).join(",\n-> ")}`);

	return JOSE;
}
