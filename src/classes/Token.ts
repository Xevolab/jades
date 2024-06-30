/*
 * Author    : Francesco
 * Created at: 2024-06-29 21:04
 * Edited by : Francesco
 * Edited at : 2024-06-30 15:03
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

// Classes
import ProtectedHeaders from "./ProtectedHeaders";
import UnprotectedHeaders from "./UnprotectedHeaders";
// Utils
import encodeHeaders from "../utils/encodeHeaders";
// Types
import type { SignAlg } from "../types";
import { KeyObject } from "crypto";
import calculateSignature, { checkKeyType, digestAlg } from "../utils/sign";

import { createHash } from "crypto";

export default class Token {
	/**
	 * Protected headers of the token
	 * @var {object}
	*/
	private protectedHeader: ProtectedHeaders = new ProtectedHeaders({});
	/**
	 * Unprotected headers of the token
	 * @var {object}
	 */
	private header: UnprotectedHeaders = new UnprotectedHeaders({});

	/**
	 * The claim of the token (aka payload)
	 * @var {string}
	 */
	private claim: string;

	/**
	 * The signature of the token
	 * @var {Buffer}
	 */
	private signature: Buffer = Buffer.from("");

	constructor(
		_claim: string | object
	) {
		// --> Validating payload
		const claim = typeof _claim === "string" ? _claim : JSON.stringify(_claim);
		this.claim = Buffer.from(new TextEncoder().encode(claim)).toString("base64url");
	}

	/**
	 * Set the protected headers of the token.
	 *
	 * @param {ProtectedHeaders} headers The protected headers of the token.
	 *
	 * @returns {void}
	 */
	public setProtectedHeaders(headers: ProtectedHeaders): void {
		this.protectedHeader = headers;
	}

	/**
	 * Set the unprotected headers of the token.
	 *
	 * @param {UnprotectedHeaders} headers The unprotected headers of the token.
	 *
	 * @returns {void}
	 */
	public setUnprotectedHeaders(headers: UnprotectedHeaders): void {
		this.header = headers;
	}

	/**
	 * Method to use a detached signature for this token.
	 * This will require you to pass a `sigD` header value (validation not yet implemented), and will
	 * also remove the claim from the token in accordance with the detached signature requirements.
	 *
	 * @param {Object}   sigD  The detached signature object
	 *
	 * @returns {void}
	 */
	public setDetachedSignature(sigD: Object): void {
		this.protectedHeader.setDetached(sigD);
		this.claim = "";
	}

	/**
	 * Method to get the hased value to be signed.
	 *
	 * @param   {SignAlg}  alg  The algorithm to use to sign the token.
	 *
	 * @returns {Buffer}        The hashed value to be signed.
	 */
	public getHash(alg: SignAlg): Buffer {
		return createHash(digestAlg(alg))
			.update(`${this.protectedHeader.toString()}.${this.claim}`)
			.digest();
	}

	/**
	 * Set the signature of the token.
	 *
	 * @param {Buffer} signature The signature of the token.
	 *
	 * @returns
	 */
	public setSignature(alg: SignAlg, signature: Buffer): void {
		this.signature = signature;
		this.protectedHeader.addHeaders({ alg });
	}

	/**
	 * Sign the token using the specified algorithm and key.
	 *
	 * @param   {SignAlg}    alg  Algorithm to use to sign the token
	 * @param   {KeyObject}  key  Key to use to sign the token
	 *
	 * @return  {string}          Base64url encoded signature
	 */
	public sign(alg: SignAlg, key: KeyObject): string {
		// Checking the key type
		checkKeyType(alg, key);
		this.protectedHeader.addHeaders({ alg });
		// Signing the token
		this.signature = calculateSignature(alg, key, Buffer.from(`${this.protectedHeader.toString()}.${this.claim}`));

		return this.signature.toString("base64url");
	}

	/**
	 * Export the token to a string using in compact serialization.
	 *
	 * @return  {string}    The token in compact serialization.
	 */
	public toString(): string {
		return `${this.protectedHeader.toString()}.${this.claim}.${this.signature.toString("base64url")}`;
	}

	/**
	 * Export the token to an object.
	 *
	 * @return  {object}    The token in object form.
	 */
	public toObject(): object {
		return {
			protected: this.protectedHeader.toString(),
			header: this.header.toString(),
			payload: this.claim,
			signature: this.signature.toString("base64url"),
		};
	}

};
