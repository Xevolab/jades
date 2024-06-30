/*
 * Author    : Francesco
 * Created at: 2023-06-02 20:33
 * Edited by : Francesco
 * Edited at : 2024-06-30 15:04
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { sign, KeyObject, SignKeyObjectInput, constants } from 'crypto';

import type { SignAlg } from "../types";

/**
 * Returns the digest algorithm for the given signature algorithm.
 *
 * @param   {string}  alg  The signature algorithm
 *
 * @return  {string}       The digest algorithm to be used
 */
export function digestAlg(alg: string): string {
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
			throw new Error(`alg ${alg} is not supported`);
	}
}

/**
 * Returns the key object for the given signature algorithm, adding necessary properties if needed
 *
 * @param   {SignAlg}    alg  The signature algorithm
 * @param   {KeyObject}  key  The key object
 *
 * @return  {KeyObject}       The modified (if needed) key object
 */
function keyForAlg(alg: SignAlg, key: KeyObject): KeyObject | SignKeyObjectInput {

	if (alg.startsWith('RS')) {
		if (key.asymmetricKeyType !== 'rsa')
			throw new TypeError(`invalid key for alg ${alg}, must be a private RSA key`);
	} else if (alg.startsWith('ES')) {
		if (key.asymmetricKeyType !== 'ec')
			throw new TypeError(`invalid key for alg ${alg}, must be a private EC key`);

		return { dsaEncoding: 'ieee-p1363', key };
	}
	else if (alg.startsWith('PS')) {
		if (key.asymmetricKeyType !== 'rsa')
			throw new TypeError(`invalid key for alg ${alg}, must be a private RSA key`);

		return {
			padding: constants.RSA_PKCS1_PSS_PADDING,
			saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
			key
		}
	}
	else {
		throw new TypeError(`alg ${alg} is not supported`);
	}

	return key;

}

/**
 * Throw an error if the key is not valid for the given algorithm.
 *
 * @param   {SignAlg}    alg  The signature algorithm
 * @param   {KeyObject}  key  The key object
 *
 * @return  {void}
 */
export function checkKeyType(alg: SignAlg, key: KeyObject): void {
	keyForAlg(alg, key);

	// RS and PS keys must have at least 2048 modulus bits
	if (alg.startsWith('RS') || alg.startsWith('PS')) {
		if (!key.asymmetricKeyDetails || !key.asymmetricKeyDetails.modulusLength || key.asymmetricKeyDetails?.modulusLength < 2048)
			throw new TypeError(`invalid key for alg ${alg}, must have at least 2048 modulus bits`);
	}

	// ES keys must be P-256, P-384 or P-521 based on the algorithm name
	if (alg.startsWith('ES')) {

		if (!key.asymmetricKeyDetails || !key.asymmetricKeyDetails.namedCurve)
			throw new TypeError(`invalid key for alg ${alg}, must have a namedCurve property`);

		const curve = key.asymmetricKeyDetails.namedCurve;
		const curveNames: { [key: string]: string } = {
			prime256v1: 'P-256',
			secp384r1: 'P-384',
			secp521r1: 'P-521'
		}
		const expectedCurve: { [key: string]: string } = {
			ES256: 'P-256',
			ES384: 'P-384',
			ES512: 'P-521'
		}

		if (curveNames[curve] !== expectedCurve[alg])
			throw new TypeError(`invalid key for alg ${alg}, must be a ${expectedCurve[alg]} key`);

	}

}

const calculateSignature = (alg: SignAlg, key: KeyObject, data: Buffer): Buffer => {
	// return jwa(alg).sign(data, key.export({ format: 'pem', type: 'pkcs1' }).toString('ascii'));
	return sign(digestAlg(alg), data, keyForAlg(alg, key));
};

export default calculateSignature;
