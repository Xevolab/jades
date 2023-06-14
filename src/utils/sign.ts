/*
 * Author    : Francesco
 * Created at: 2023-06-02 20:33
 * Edited by : Francesco
 * Edited at : 2023-06-13 22:11
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { createHmac, sign, KeyObject } from 'crypto';

import type { SignAlg } from "../types";

export function digestAlg(alg: string) {
	switch (alg) {
		case 'PS256':
		case 'RS256':
		case 'ES256':
			return 'sha256';

		case 'PS384':
		case 'RS384':
		case 'ES384':
			return 'sha384';

		case 'PS512':
		case 'RS512':
		case 'ES512':
			return 'sha512';

		default:
			throw new Error(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
	}
}

const calculateSignature = (alg: SignAlg, key: KeyObject, data: Buffer) => {

	console.log(key)
	return sign(digestAlg(alg), data, key);

};

export default calculateSignature;
