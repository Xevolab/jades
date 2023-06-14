/*
 * Author    : Francesco
 * Created at: 2023-06-13 21:20
 * Edited by : Francesco
 * Edited at : 2023-06-13 22:06
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

const { validateUnprotected } = require("../schemas/schemas");

export default function generateUnprotectedHeaders(unprotectedHeaders: any/* , certs */) {

	// Checking the unsigned headers against the schema if present
	if (Object.keys(unprotectedHeaders).length > 0) {
		const validationResult = validateUnprotected(unprotectedHeaders);

		if (!validationResult)
			throw new Error(`Invalid JOSE headers; \n-> ${validateUnprotected.errors.map((error: Error, i: number) => `${i}. ${error.message}`).join(",\n-> ")}`);

	}

	return Object.keys(unprotectedHeaders).length > 0 ? unprotectedHeaders : null;

}
