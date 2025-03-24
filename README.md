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
const {Token, ProtectedHeaders, UnprotectedHeaders, parseCerts, generateX5c} = require("@xevolab/jades");
// or
import {Token, ProtectedHeaders, UnprotectedHeaders, parseCerts, generateX5c} from "@xevolab/jades";
```

> For more information on the JAdES standard and the ETSI TS 119 182 document, please refer to the [ETSI website](https://www.etsi.org/standards-search?search=jades).
>
> 🚨 I also created a Notion page with some summarized information from the ETSI document and it's available [here](https://xevolab.notion.site/JAdES-JSON-Advanced-Electronic-Signature-5995372f807c49489ff9c4abf8177cf8?pvs=4). Please, consider taking a look, any feedback is welcome.

# Usage

## Classes

The library exports 3 classes: `Token`, `ProtectedHeaders`, `UnprotectedHeaders` and some helper functions.

To create a signed token, we can instantiate a new `Token` object, add the necessary headers and sign the payload.

```typescript
const payload = { /* Something */ };
const jades = new Token(payload);


const headers = new ProtectedHeaders({
	/*      Protected headers      */
	/* of type ExtProtectedHeaders */
});
jades.setProtectedHeaders(headers);

const unprotectedHeaders = new UnprotectedHeaders({
	/*      Unprotected headers      */
	/* of type ExtUnprotectedHeaders */
});
jades.setUnprotectedHeaders(unprotectedHeaders); // Optional
```
After the signed and unsigned headers have been gathered by the library, these are checked against the publically available JSON schema for JAdES signatures. If the headers are not valid, the library will throw an error.

The token can be signed using:
- the `sign` method, passing it a `KeyObject` and a `SignAlg` algorithm;
- utilizing the `getHash` method to get the hash of the payload, sign it using a custom method separately and set it using the `setSignature` method.

The token can also be signed using a detached signature, by calling the `setDetachedSignature` method and providing it the `sigD` value. The value is currently not validated by the library, just using the schema.

Once the token is signed, it can be retrieved:
- using the `toString` for a compact representation;
- using the `toJSON` method for a JSON representation.

## `parseCerts(certs)`
The `parseCerts` function takes a string containing one or more PEM encoded certificates and returns an array of `X509Certificate[]` objects.

## `generateX5c(cert)`, `generateX5tS256(cert)`, `generateX5tO(cert, alg)`, `generateX5ts(cert, alg)`
These functions take a `X509Certificate[]` object array and return the corresponding header value.

## `generateKid(cert)`
> **Warning:** This function is not fully implemented yet.

This function takes a `X509Certificate[]` object array and returns the corresponding `kid` header value.

# Example

```javascript
const {Token, ProtectedHeaders, parseCerts, generateX5c} = require("@xevolab/jades");
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

const jades = new Token(payload);

jades.setProtectedHeaders(new ProtectedHeaders({
	x5c: generateX5c(certs)
}));
jades.sign("RS256", key);

const token = jades.toString();
console.log(token);
```
