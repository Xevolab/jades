# JAdES Signatures


## Introduction

This repository contains a basic implementation of the JAdES standard for digital signatures. The implementation is based on the [ETSI TS 119 182](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf) standard.

## Usage

The library exports a function `sign` that takes a object payload and a parameter object as arguments. The payload object should contain the data to be signed. The parameter object should contain the following properties:

```
{
	serialization: "compact",
	detached: false,

	key: null,
	cert: certs: null,

	alg: "RS256",
	cty: null,

	signedHeaders: {},
	unsignedHeaders: {}
}
```

* `serialization` - The serialization format of the signature. Can be either `compact` or `json`. Defaults to `compact`.
* `detached` - Whether the signature should be detached. Defaults to `false`.
* `key` - The private key to sign the payload with in PEM format. Defaults to `null`.
* `cert` - The certificate to sign the payload with in PEM format, can contain a chain of certificates in PEM format. Defaults to `null`.
* `alg` - The algorithm to use for the signature. Defaults to `RS256`.
* `cty` - The content type of the payload. Defaults to `null`.
* `signedHeaders` - A object containing the headers to be signed. Defaults to `{}`.
* `unsignedHeaders` - A object containing the headers to be added to the signature but not signed. Defaults to `{}`.

The `signedHeaders` object accepts the following properties:

```
{
	kid: null,

	x5u: null,
	x5c: null,
	autoIncludeX5c: true,
	x5tS256: null,
	autoIncludeX5tS256: false,
	x5tO: null,
	sigX5ts: null,
	autoIncludeSigX5ts: false,

	srCms: null,
	srAts: null,
	sigPl: null,
	sigPId: null,

	sigD: null,

	adoTst: null,
}
```

* `kid` - The key id of the key used to sign the payload. If the value is `null` the key id will be generated from the first certificate in certs.
* `x5u` - The URL to the certificate used to sign the payload.
* `x5c` - The certificate chain used to sign the payload.
* `autoIncludeX5c` - Whether to automatically include the certificate chain in the signature. Defaults to `true`.
* `x5tS256` - The SHA-256 thumbprint of the certificate used to sign the payload.
* `autoIncludeX5tS256` - Whether to automatically include the SHA-256 thumbprint of the certificate used to sign the payload in the signature. Defaults to `false`.
* `x5tO` - The SHA-1 thumbprint of the certificate used to sign the payload.
* `sigX5ts` - The certificate chain used to sign the payload.
* `autoIncludeSigX5ts` - Whether to automatically include the certificate chain used to sign the payload in the signature. Defaults to `false`.
* `srCms` - The signer commitments.
* `srAts` - The signer attributes.
* `sigPl` - The signature production place.
* `sigPId` - The signature policy identifier.
* `sigD` - From the ETSI TS 119 182 document: "a new JSON header parameter that allows to identify one or more detached data objects
which, suitably processed and concatenated, form the detached JWS Payload". Defaults to `null`
* `adoTst` - A signed data time-stamp.

At the moment, the `srCms`, `srAts`, `sigPl`, `sigPId`, `sigD` and `adoTst` properties are accepted but not processed.

After the signed and unsigned headers have been calculated by the library, these are checked against the publically available JSON schema for JAdES signatures. If the headers are not valid, the library will throw an error.

The `sign` function returns a string containing the signature or an object, depending on the serialization chosen.

### Example

```
const sign = require("@xevolab/jades");

const payload = {
	"hello": "world"
};

const options = {
	serialization: "compact",
	alg: "RS256",

	key: fs.readFileSync("private.key", "ascii"),
	cert: fs.readFileSync("certificate.pem", "ascii"),

	// ...
}

const signature = sign(payload, options);
console.log(signature);
```
