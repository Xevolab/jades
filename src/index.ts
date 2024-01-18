/*
 * Author    : Francesco
 * Created at: 2023-06-02 13:35
 * Edited by : Francesco
 * Edited at : 2023-12-04 17:07
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

import { X509Certificate, KeyObject } from "crypto";
import calculateSignature, { checkKeyType } from "./utils/sign";

import generateProtectedHeaders from "./utils/generateProtectedHeaders";
import generateUnprotectedHeaders from "./utils/generateUnprotectedHeaders";

import type { SignAlg } from "./types";
export * from "./types";

export function parseCerts(certs: string): X509Certificate[] {
	return certs.split("-----END CERTIFICATE-----").filter((j: string) => j.trim() !== "").map((j: string) => new X509Certificate(`${j}-----END CERTIFICATE-----`));
}

export default function sign(p: string | object, {
	serialization = "compact",
	detached = false,

	key,

	alg = "RS256",
	cty = null,

	protectedHeaders = {},
	unprotectedHeaders = {},

	// ...rest
}: {
	serialization?: "compact" | "json",
	detached?: boolean,

	key: KeyObject,
	alg: SignAlg,
	cty?: null | string,

	protectedHeaders?: object,
	unprotectedHeaders?: object,
}): (string | { payload: string, signature: string, protected: string, header?: string }) {

	// --> Validating payload

	let payload = p;
	if (typeof p === "object") payload = JSON.stringify(payload);
	if (typeof payload !== "string") throw new Error("Invalid payload; needs to be a string or an object.");

	// --> Loading the key(s)

	if (!key || !(key instanceof KeyObject)) throw new Error("Invalid key; needs to be a KeyObject.");

	checkKeyType(alg, key);

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

	const algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", /*"PS256", "PS384", "PS512"*/];
	if (!algs.includes(alg))
		throw new Error(`Invalid alg; needs to be one of: ${algs.join(", ")}.\nIt's possibile the algorithm you selected is not yet supported, please consider contributing!`);

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
	// eslint-disable-next-line no-param-reassign
	if (cty !== null && cty.startsWith("application/")) cty = cty.substring(12);
	if (detached && cty !== null) throw new Error("Invalid cty; needs to be null when detached is true.");

	const protectedH = generateProtectedHeaders(protectedHeaders, { alg, cty, detached });
	const unsignedHeaders = generateUnprotectedHeaders(unprotectedHeaders);

	/**
	 * Unsigned JWS Headers
	 * ETSI TS 119 182-1 - Section 5.3
	 *
	 * JWS unsigned headers are only allowed when the serialization is JSON
	 */
	if (serialization !== "json" && unsignedHeaders !== null) throw new Error("Invalid unsigned; needs to be undefined when the serialization is not JSON.");

	// --> Preparing the signature parts

	// Encoding the protected headers
	let protectedHString = Buffer.from(new TextEncoder().encode(JSON.stringify(protectedH))).toString("base64url");

	// Encoding the eventual unsigned headers
	let unsignedHeadersString = undefined;
	if (unsignedHeaders !== null) {
		unsignedHeadersString = new TextEncoder().encode(JSON.stringify(unsignedHeaders));
		unsignedHeadersString = Buffer.from(unsignedHeadersString).toString("base64url");
	}

	// Encoding the payload
	payload = Buffer.from(new TextEncoder().encode(payload)).toString("base64url");

	// --> Signing the payload
	// const signature = calculateSignature(alg, key, Buffer.from(`${protectedHString}.${payload}`)).toString("base64url");
	const signature = calculateSignature(alg, key, Buffer.from(`${protectedHString}.${payload}`)).toString("base64url");

	// --> Creating the JWS
	if (serialization === "json") {
		return {
			protected: protectedHString,
			header: unsignedHeadersString,
			payload,
			signature,
		};
	}

	return `${protectedHString}.${payload}.${signature}`;
}

export { default as generateKid } from "./utils/generateKid";
export { generateX5c, generateX5ts, generateX5tS256, generateX5o } from "./utils/generateX5";

export { default as generateCommitments } from "./utils/generateCommitments";
