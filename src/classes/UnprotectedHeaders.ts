/*
 * Author    : Francesco
 * Created at: 2024-06-29 21:20
 * Edited by : Francesco
 * Edited at : 2025-03-25 23:22
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

import encodeHeaders from "../utils/encodeHeaders";

import { validateUnprotected } from "../schemas/schemas.js";

/**
 * This class is used to manage the unprotected headers of a token.
 * Their validation is handled by the JSON schema.
 */
export default class UnprotectedHeaders {
	private header?: Object = {};

	constructor(p: any) {
		// Checking the unsigned headers against the schema if present
		if (Object.keys(p).length > 0) {
			const validationResult = validateUnprotected(p);

			if (!validationResult)
				throw new Error(`Invalid JOSE headers; \n-> ${validateUnprotected.errors.map((error: Error, i: number) => `${i}. ${error.message}`).join(",\n-> ")}`);

		}

		this.header = Object.keys(p).length > 0 ? p : undefined;
	}

	/**
	 * Get the unprotected headers of the token.
	 *
	 * @returns {Object}
	 */
	getHeaders(): Object {
		if (!this.header) throw new Error("Unprotected headers not set.");

		return this.header;
	}

	toString(): string {
		if (!this.header) throw new Error("Unprotected headers not set.");

		return encodeHeaders(this.header);
	}

};
