/*
 * Author    : Francesco
 * Created at: 2023-06-02 20:33
 * Edited by : Francesco
 * Edited at : 2023-06-02 21:12
 * 
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { createHmac, sign } from 'crypto'

const calculateSignature = (alg, key, data) => {

	if (alg.startsWith('HS')) {
		const hmac = createHmac(digestAlg(alg), key)
		hmac.update(data)
		return hmac.digest()
	}

	return sign(digestAlg(alg), data, key)
}

export function digestAlg(alg) {
	switch (alg) {
		case 'PS256':
		case 'RS256':
		case 'ES256':
		case 'HS256':
			return 'sha256'

		case 'PS384':
		case 'RS384':
		case 'ES384':
		case 'HS384':
			return 'sha384'

		case 'PS512':
		case 'RS512':
		case 'ES512':
		case 'HS512':
			return 'sha512'

		default:
			throw new Error(`alg ${alg} is not supported either by JOSE or your javascript runtime`)
	}
}

export default calculateSignature
