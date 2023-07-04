# JAdES Signatures


## Introduction

This repository contains a basic implementation of the JAdES standard for digital signatures. The implementation is based on the [ETSI TS 119 182](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf) standard.

## Installation

In order to install the library, run the following command:

```bash
npm install @xevolab/jades
```

You will be able to import the library using the following syntax:

```javascript
const {default: sign, parseCerts, generateX5c} = require("@xevolab/jades");
// or
import {default as sign, parseCerts, generateX5c} from "@xevolab/jades";
```

> For more information on the JAdES standard and the ETSI TS 119 182 document, please refer to the [ETSI website](https://www.etsi.org/standards-search?search=jades).
>
> 🚨 I also created a Notion page with some summarized information from the ETSI document and it's available [here](https://franc0.notion.site/JAdES-JSON-Advanced-Electronic-Signature-0e85e52dae8c418f8d81ecca36d2a22e?pvs=4). Please, consider taking a look, any feedback is welcome.

# Usage

## `sign(payload, options)`

The library exports the default function `sign` that takes a object payload and a parameter object as arguments. The payload object should contain the data to be signed. The parameter object should contain the following properties:

```typescript
let payload = { /* Something */ };

let options = {
	serialization: "compact" | "json",
	detached: boolean,

	key: KeyObject,
	alg: SignAlg,
	cty: null | string,

	protectedHeaders: object,
	unprotectedHeaders: object,
};
```

* `serialization` - The serialization format of the signature. Can be either `compact` or `json`. Defaults to `compact`.
* `detached` - Whether the signature should be detached. Defaults to `false`.

  Currently, the library does not support detached signatures. This property is accepted but not used by the code.

* `key` - The private key to sign the payload with (as a `KeyObject` object). This property is required.
* `alg` - The algorithm to use for the signature. Defaults to `RS256`.

	Please note that currently the only supported algorithms are `RS256`, `RS384` and `RS512`. Please, consider contributing if you would like to see more algorithms in the future.

* `cty` - The content type of the payload. Defaults to `null`.
* `signedHeaders` - A object containing the headers to be signed. Defaults to `{}`.
* `unsignedHeaders` - A object containing the headers to be added to the signature but not signed. Defaults to `{}`.

The `signedHeaders` object accepts the following properties:

```typescript
{
	kid?: null | string,
	x5u?: null | string,
	x5c?: null | string[],
	x5tS256?: null | string,
	x5tO?: null | { digAlg: string, sigVal: string },
	sigX5ts?: null | { digAlg: string, sigVal: string }[],
	srCms?: null | { commId: object }[],
	srAts?: null | object[],
	sigPl?: null | object,
	sigPId?: null | object,
	sigD?: null | object,
	adoTst?: null | object[]
}
```

* `kid` - The key id of the key used to sign the payload.
* `x5u` - The URL to the certificate used to sign the payload.
* `x5c` - The certificate chain used to sign the payload.
* `x5tS256` - The SHA-256 thumbprint of the certificate used to sign the payload.
* `x5tO` - The SHA-1 thumbprint of the certificate used to sign the payload.
* `sigX5ts` - The certificate chain used to sign the payload.
* `srCms` - The signer commitments.
* `srAts` - The signer attributes.
* `sigPl` - The signature production place.
* `sigPId` - The signature policy identifier.
* `sigD` - From the ETSI TS 119 182 document: "a new JSON header parameter that allows to identify one or more detached data objects
which, suitably processed and concatenated, form the detached JWS Payload". Defaults to `null`
* `adoTst` - A signed data time-stamp.

At the moment, the `srAts`, `sigPl`, `sigPId`, `sigD` and `adoTst` properties are accepted but not validated by the code.

The `unprotectedHeaders` are also only accepted but not validated by the code.

After the signed and unsigned headers have been gathered by the library, these are checked against the publically available JSON schema for JAdES signatures. If the headers are not valid, the library will throw an error.

The `sign` function returns a string or an object containing the signature, depending on the serialization chosen.

## `parseCerts(certs)`
The `parseCerts` function takes a string containing one or more PEM encoded certificates and returns an array of `X509Certificate[]` objects.

## `generateX5c(cert)`, `generateX5tS256(cert)`, `generateX5tO(cert, alg)`, `generateX5ts(cert, alg)`
These functions take a `X509Certificate[]` object array and return the corresponding header value.

## `generateKid(cert)`
> **Warning:** This function is not fully implemented yet.

This function takes a `X509Certificate[]` object array and returns the corresponding `kid` header value.

# Example

```javascript
const {default: sign, parseCerts, generateX5c} = require("@xevolab/jades");
const createPrivateKey = require("crypto").createPrivateKey;

const payload = {
	"hello": "world"
};

const key = createPrivateKey({
	key: fs.readFileSync("private-key.pem", "ascii"),
	format: "pem",
	type: "pkcs1"
});
const certs = parseCerts(fs.readFileSync("certificate.pem", "ascii"));

const options = {
	serialization: "compact",
	alg: "RS256",

	key,

	protectedHeaders: {
		x5c: generateX5c(certs)
	}
}

const signature = sign(payload, options);
console.log(signature);
```
