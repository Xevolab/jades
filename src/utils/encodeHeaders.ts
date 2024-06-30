/*
 * Author    : Francesco
 * Created at: 2024-06-29 21:28
 * Edited by : Francesco
 * Edited at : 2024-06-29 21:28
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

/**
 * Helper function that transforms the headers object into a base64url string.
 *
 * @param   {object}  headers  The headers in object form.
 *
 * @return  {string}           The headers in base64url string form.
 */
export default function encodeHeaders(headers: object): string {
	return Buffer.from(new TextEncoder().encode(JSON.stringify(headers))).toString("base64url");
}
