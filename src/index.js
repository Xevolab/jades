/*
 * Author    : Francesco
 * Created at: 2023-06-02 13:35
 * Edited by : Francesco
 * Edited at : 2023-06-09 16:44
 * 
 * Copyright (c) 2023 Xevolab S.R.L.
 */

/**
 *  ! Please note that this is a draft and it's not ready for production. !
 * 
 * This is a library that implements the ETSI TS 119 312 standard.
 * Please, consider visiting the official website for more information:
 * https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf
 * 
 */

import { createPrivateKey, createPublicKey, X509Certificate, createHash } from "crypto";
import calculateSignature from "./utils/sign.js";

// Schemas
import Ajv from "ajv";
import addFormats from "ajv-formats"
const ajv = new Ajv({
	allErrors: true,
	strict: false,
});
addFormats(ajv);

import fs from "fs";
import path from 'path'
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

ajv.addSchema({
	"$id": "19182-jsonSchema.json",
	...JSON.parse(fs.readFileSync(__dirname + "/schemas/19182-jsonSchema.json", "utf-8"))
});
ajv.addSchema({
	"$id": "19182-protected-jsonSchema.json",
	...JSON.parse(fs.readFileSync(__dirname + "/schemas/19182-protected-jsonSchema.json", "utf-8"))
});
ajv.addSchema({
	"$id": "19182-unprotected-jsonSchema.json",
	...JSON.parse(fs.readFileSync(__dirname + "/schemas/19182-unprotected-jsonSchema.json", "utf-8"))
});
ajv.addSchema({
	"$id": "rfcs/rfc7515.json",
	...JSON.parse(fs.readFileSync(__dirname + "/schemas/rfcs/rfc7515.json", "utf-8"))
});
ajv.addSchema({
	"$id": "rfcs/rfc7517.json",
	...JSON.parse(fs.readFileSync(__dirname + "/schemas/rfcs/rfc7517.json", "utf-8"))
});
ajv.addSchema({
	"$id": "rfcs/rfc7797.json",
	...JSON.parse(fs.readFileSync(__dirname + "/schemas/rfcs/rfc7797.json", "utf-8"))
});

const validateProtected = ajv.getSchema("19182-protected-jsonSchema.json");
const validateUnprotected = ajv.getSchema("19182-unprotected-jsonSchema.json");

import generateKid from "./utils/generateKid.js";
import { base64url } from "jose";

/**
 * [export description]
 *
 * @param   {[type]}  payload  [payload description]
 *
 * @return  {[type]}           [return description]
 */
export function sign(payload, {
	serialization = "compact",
	detached = false,

	key = null,
	cert: certs = null,

	alg = "RS256",
	cty = null,

	signedHeaders = {},
	unsignedHeaders = {},

	...rest
}) {

	// --> Validating payload

	if (typeof payload === "object") payload = JSON.stringify(payload);
	if (typeof payload !== "string") throw new Error("Invalid payload; needs to be a string or an object.");

	// --> Loading the key(s)

	if (!key) throw new Error("Invalid key; needs to be a string.");

	key = createPrivateKey({
		key: key,
		format: 'pem',
		type: 'pkcs8'
	});

	let cert = createPublicKey({
		key: certs,
		format: 'pem',
		type: 'pkcs1'
	});
	certs = certs.split("-----END CERTIFICATE-----").filter(c => c.trim() !== "").map((cert) => new X509Certificate(cert + "-----END CERTIFICATE-----"));

	// --> Validating options

	/**
	 * Validating `serialization` of JWS signature serialization
	 * ETSI TS 119 182-1 - Section 4
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-3
	 */
	if (!["compact", "json"].includes(serialization.toLowerCase()))
		throw new Error("Invalid serialization; needs to be one of: compact, json.");

	// Validating if the payload is detached
	// ETSI TS 119 182-1 - Section 5.2.8
	if (typeof detached !== "boolean")
		throw new Error("Invalid detached; needs to be a boolean.");

	/**
	 * `alg`
	 * ETSI TS 119 182-1 - Section 5.1.2
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
	 * └-> https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
	 * View also: ETSI TS 119 312
	 */

	const algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512"];
	if (!algs.includes(alg))
		throw new Error("Invalid alg; needs to be one of: " + algs.join(", ") + ".");

	/**
	 * `cty`
	 * ETSI TS 119 182-1 - Section 5.1.3
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10
	 * └-> https://datatracker.ietf.org/doc/html/rfc2045
	 * 
	 * It is suggested to remove the `application/` prefix from the `cty` value.
	 * `cty` must be `null` when `detached` is `true`.
	 * `cty` should not be present if:
	 *  - the payload is a JWS
	 *  - the type is implied by the Payload
	 */
	if (!detached && cty !== null && typeof cty !== "string")
		throw new Error("Invalid cty; needs to be a string.");
	if (cty !== null && cty.startsWith("application/")) cty = cty.substring(12);
	if (detached && cty !== null) throw new Error("Invalid cty; needs to be null when detached is true.");

	let {
		kid = null,

		x5u = null,
		x5c = null,
		autoIncludeX5c = true,
		x5tS256 = null,
		autoIncludeX5tS256 = false,
		x5tO = null,
		sigX5ts = null,
		autoIncludeSigX5ts = false,

		// These properties are part of the standard but are not directly
		// checked by the library. Using the `validate` function, you can
		// check if the payload is valid or not against the official schema.
		srCms = null,
		srAts = null,
		sigPl = null,
		sigPId = null,

		sigD = null,

		// These properties are not yet supported by the library but could be
		// in the future.
		// Please, consider contributing to the project if you want to help.
		adoTst = null,
	} = signedHeaders;


	/**
	 * `kid`
	 * ETSI TS 119 182-1 - Section 5.1.4
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
	 */
	if (kid !== null && typeof kid !== "string") throw new Error("Invalid kid; needs to be a string.");
	if (kid !== null && !/^[a-zA-Z0-9-_]+$/g.test(kid)) throw new Error("Invalid kid; needs to be a base64 string.");

	// The `kid` is automatically included if it's not provided
	if (kid === null) kid = generateKid(certs[0]);

	/**
	 * `x5u`
	 * ETSI TS 119 182-1 - Section 5.1.5
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5
	 * 
	 * `x5u` must be a URI that refers to a resource for the X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS.
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
	 * The certificate chain must be ordered such that each certificate contains the public key of the subsequent certificate.
	 * The first certificate must correspond to the key used to digitally sign the JWS.
	 */
	if (x5c !== null && Array.isArray(x5c)) throw new Error("Invalid x5c; needs to be an array.");
	if (x5c !== null && x5c.length === 0) throw new Error("Invalid x5c; needs to be an array with at least one element.");
	if (x5c !== null && !x5c.every((cert) => typeof cert === "string")) throw new Error("Invalid x5c; needs to be an array of strings.");
	if (x5c !== null && !x5c.every((cert) => /^[a-zA-Z0-9=\/+]+$/g.test(cert))) throw new Error("Invalid x5c; needs to be an array of base64 strings.");

	// The `x5c` is automatically included in the JOSE header if `autoIncludeX5c` is `true`
	if (autoIncludeX5c && x5c !== null) throw new Error("Invalid autoIncludeX5c; needs to be false when x5c is not null.");
	if (autoIncludeX5c && !cert) throw new Error("Invalid autoIncludeX5c; needs to be false when cert is null.");
	if (autoIncludeX5c) x5c = certs.map(cert => cert.raw.toString("base64"));

	/**
	 * `x5t#256`
	 * ETSI TS 119 182-1 - Section 5.1.7
	 * └-> https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8
	 * 
	 * `x5t#256` must be a base64url encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS.
	 */
	if (x5tS256 !== null && typeof x5tS256 !== "string") throw new Error("Invalid x5tS256; needs to be a string.");
	if (x5tS256 !== null && !/^[a-zA-Z0-9-_]+$/g.test(x5tS256)) throw new Error("Invalid x5tS256; needs to be a base64url string.");
	if (x5tS256 !== null && x5c !== null) throw new Error("Invalid x5tS256; needs to be null when x5c is not null.");

	// The `x5t#256` is automatically included in the JOSE header if `autoIncludeX5tS256` is `true`
	if (autoIncludeX5tS256 && x5tS256 !== null) throw new Error("Invalid autoIncludeX5tS256; needs to be false when x5tS256 is not null.");
	if (autoIncludeX5tS256 && !cert) throw new Error("Invalid autoIncludeX5tS256; needs to be false when cert is null.");
	if (autoIncludeX5tS256) x5tS256 = createHash("sha256").update(cert.export({ type: "spki", format: "der" })).digest("base64url");

	/**
	 * `x5t#o`
	 * ETSI TS 119 182-1 - Section 5.2.2.2
	 * 
	 * `x5t#o` must be an object with the following properties:
	 *  - `digAlg` must be a string containing the digest algorithm used to compute the thumbprint.
	 *  - `digVal` must be a base64url encoded thumbprint of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign the JWS.
	 */
	if (x5tO !== null && typeof x5tO !== "object") throw new Error("Invalid x5tO; needs to be an object.");
	if (x5tO !== null && !x5tO.hasOwnProperty("digAlg")) throw new Error("Invalid x5tO; needs to have a property named `digAlg`.");
	if (x5tO !== null && !x5tO.hasOwnProperty("digVal")) throw new Error("Invalid x5tO; needs to have a property named `digVal`.");
	if (x5tO !== null && typeof x5tO.digAlg !== "string") throw new Error("Invalid x5tO; `digAlg` needs to be a string.");
	if (x5tO !== null && typeof x5tO.digVal !== "string") throw new Error("Invalid x5tO; `digVal` needs to be a string.");
	if (x5tO !== null && !/^[a-zA-Z0-9-_]+$/g.test(x5tO.digVal)) throw new Error("Invalid x5tO; `digVal` needs to be a base64url string.");

	/**
	 * `sigX5ts`
	 * ETSI TS 119 182-1 - Section 5.2.2.3
	 * 
	 * `sigX5ts` must be an array of at least 2 objects with the same properties as `x5t#o` (see above).
	 * The first object must contain the thumbprint of the certificate used to sign the JWS.
	 * Each object may contain digest values computed with the algorithm SHA-256.
	 */
	if (sigX5ts !== null && !Array.isArray(sigX5ts)) throw new Error("Invalid sigX5ts; needs to be an array.");
	if (sigX5ts !== null && sigX5ts.length < 2) throw new Error("Invalid sigX5ts; needs to be an array with at least 2 elements.");
	if (sigX5ts !== null && !sigX5ts.every((x5tO) => typeof x5tO === "object")) throw new Error("Invalid sigX5ts; needs to be an array of objects.");

	// The `sigX5ts` is automatically included in the JOSE header if `autoIncludeSigX5ts` is `true`
	if (autoIncludeSigX5ts && sigX5ts !== null) throw new Error("Invalid autoIncludeSigX5ts; needs to be false when sigX5ts is not null.");
	if (autoIncludeSigX5ts && !cert) throw new Error("Invalid autoIncludeSigX5ts; needs to be false when cert is null.");
	if (autoIncludeSigX5ts) {
		sigX5ts = certs.map((cert) => ({
			digAlg: "SHA-256",
			digVal: createHash("sha256").update(cert.export({ type: "spki", format: "der" })).digest("base64url")
		}));
	}

	// ETSI TS 119 182-1 - Section 5.1.7
	// A JAdES signature shall have at least one of the following header parameters in its JWS Protected Header: x5t#S256, x5c, x5t#o, sigX5ts.
	if (x5tS256 === null && x5c === null && x5tO === null && sigX5ts === null) throw new Error("Invalid JAdES signature; needs to have at least one of the following header parameters in its JWS Protected Header: x5t#S256, x5c, x5t#o, sigX5ts.");


	/**
	 * `sigD`
	 * ETSI TS 119 182-1 - Section 5.2.8
	 * 
	 * `sigD` is an object referencing one or more detached data objects, meaning that this property is only present when the JWS Payload is detached.
	 * ⚠️ The `sigD` header parameter is not checked by this library.
	 */
	if (sigD !== null && typeof sigD !== "object") throw new Error("Invalid sigD; needs to be an object.");
	if (sigD !== null && !detached) throw new Error("Invalid sigD; needs to be null when detached is false.");

	/**
	 * Unsigned JWS Headers
	 * ETSI TS 119 182-1 - Section 5.3
	 * 
	 * JWS unsigned headers are only allowed when the serialization is JSON
	 */
	if (serialization !== "json" && Object.keys(unsignedHeaders).length > 0) throw new Error("Invalid unsigned; needs to be undefined when the serialization is not JSON.");

	// --> Preparing for the signature

	// Creating the JOSE headers
	const JOSE = {
		alg,
		cty,
		kid,
		x5u,
		x5c,
		["x5t#S256"]: x5tS256,
		["x5t#o"]: x5tO,
		sigX5ts,

		// sigT: new Date().toISOString(),
		sigD,
		sigPl,
		sigPId,
		srCms,
		srAts,
		adoTst,

		/**
		 * `b64`
		 * ETSI TS 119 182-1 - Section 5.1.10
		 * └-> https://datatracker.ietf.org/doc/html/rfc7797#section-3
		 */
		b64: false,
	}
	// Removing all null or undefined values from the JOSE headers
	Object.keys(JOSE).forEach((key) => (JOSE[key] === null || JOSE[key] === undefined) && delete JOSE[key]);

	// Calculating the `crit` header parameter
	const critParameters = ["x5t#o", "sigX5ts", "sigT", "sigD", "sigPl", "sigPId", "srCms", "srAts", "adoTst", "b64"];
	JOSE.crit = critParameters.filter((parameter) => JOSE.hasOwnProperty(parameter));

	// --> Checking against the schema

	// Checking the JOSE headers against the schema
	let validationResult = validateProtected(JOSE);
	if (!validationResult) {
		throw new Error("Invalid JOSE headers; \n-> " + validateProtected.errors.map((error, i) => i + ". " + error.message).join(",\n-> "));
	}

	// Checking the unsigned headers against the schema if present
	if (Object.keys(unsignedHeaders).length > 0) {
		validationResult = validateUnprotected(unsignedHeaders);
		if (!validationResult) {
			throw new Error("Invalid unsigned headers; \n-> " + validateUnprotected.errors.map((error, i) => i + ". " + error.message).join(",\n-> "));
		}
	}

	// --> Preparing the signature parts

	// Encoding the JOSE headers
	let JOSEString = new TextEncoder().encode(JSON.stringify(JOSE));
	JOSEString = base64url.encode(JOSEString);

	// Encoding the eventual unsigned headers
	let unsignedHeadersString;
	if (Object.keys(unsignedHeaders).length > 0) {
		unsignedHeadersString = new TextEncoder().encode(JSON.stringify(unsignedHeaders));
		unsignedHeadersString = base64url.encode(unsignedHeadersString);
	}

	// Encoding the payload
	payload = new TextEncoder().encode(payload)
	payload = base64url.encode(payload);

	// --> Signing the payload
	let signature = calculateSignature(alg, key, JOSEString + "." + payload).toString("base64url");

	// --> Creating the JWS
	if (serialization === "json") {
		return {
			protected: JOSEString,
			header: unsignedHeadersString,
			payload,
			signature,
		}
	}
	else if (serialization === "compact") {
		return JOSEString + "." + payload + "." + signature;
	}
}
