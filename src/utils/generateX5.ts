/*
 * Author    : Francesco
 * Created at: 2023-06-13 20:52
 * Edited by : Francesco
 * Edited at : 2023-06-13 21:41
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { X509Certificate, createHash } from "crypto";

export function generateX5c(certs: X509Certificate[]): string[] {
	return certs.map((cert) => cert.raw.toString("base64"));
}

export function generateX5tS256(certs: X509Certificate[]): string {
	return createHash("sha256").update(certs[0].raw).digest("base64url");
}

const allowedAlgs: { [key: string]: "S384" | "S512" } = {
	SHA384: "S384",
	SHA512: "S512"
};

interface X5o { digAlg: "S384" | "S512", digVal: string };
export function generateX5o(certs: X509Certificate[], alg: "SHA384" | "SHA512"): X5o {
	if (!allowedAlgs[alg]) throw new Error(`Unsupported algorithm: ${alg}`);

	return {
		digAlg: allowedAlgs[alg],
		digVal: createHash(alg).update(certs[0].raw).digest("base64url")
	};
}

export function generateX5ts(certs: X509Certificate[], alg: "SHA384" | "SHA512"): X5o[] {
	if (!allowedAlgs[alg]) throw new Error(`Unsupported algorithm: ${alg}`);

	return certs.map((cert) => ({
		digAlg: allowedAlgs[alg],
		digVal: createHash(alg).update(cert.raw).digest("base64url")
	}));
}
