/*
 * Author    : Francesco
 * Created at: 2023-09-24 09:53
 * Edited by : Francesco
 * Edited at : 2024-06-30 16:49
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { describe, it } from "node:test";
import { expect } from "chai";

import { createPrivateKey } from "crypto";
import * as fs from "fs";

import * as jose from "jose";
import * as jws from "jws";
import { Token, ProtectedHeaders, parseCerts, generateX5c } from "../src/index";
import { SignAlg } from "../src/types";

import { Algorithm } from "jws";

const payload = { message: "Hello, world!" };

describe("sign", () => {

	describe("RS", () => {

		["2048", "4096"].forEach(keyLength => {
			describe("Key length: " + keyLength, () => {

				const key = createPrivateKey({
					key: fs.readFileSync(__dirname + `/test_rsa_${keyLength}.pem`, "ascii"),
					format: "pem",
					type: "pkcs1"
				});
				const certs = parseCerts(fs.readFileSync(__dirname + `/test_rsa_${keyLength}.crt`, "ascii"));

				["RS256", "RS384", "RS512"].forEach(alg => {
					describe("Alg: " + alg, () => {
						const token = new Token(payload);

						token.setProtectedHeaders(new ProtectedHeaders({
							x5c: generateX5c(certs)
						}));

						token.sign(alg as SignAlg, key);
						const jades = token.toString();

						it("should return a string", () => {
							expect(jades).to.be.a("string");
						});
						it("should be a valid JWS", () => {
							expect(jades.split(".").length).to.equal(3);
						});
						it("should be a valid JWS with a valid header", () => {
							expect(JSON.parse(Buffer.from(jades.split(".")[0], "base64").toString("utf8"))).to.be.an("object");
						});
						it("signature lenght should be correct", () => {
							const sigLengthHex = Buffer.from(jades.split(".")[2], "base64").toString("hex").length;

							// 2048 bits = 256 bytes = 512 hex chars
							expect(sigLengthHex).to.equal(parseInt(keyLength) / 4);
						});

						// validate with jose
						it("should be a valid JWS (JOSE)", async () => {
							let { payload: _payload/*, protectedHeaders */ } = await jose.compactVerify(jades, certs[0].publicKey);
							const returnedString = Buffer.from(_payload).toString("utf8");

							expect(returnedString).to.equal(JSON.stringify(payload));
						});

						// validate with jws
						it("should be a valid JWS (JWS)", () => {
							expect(jws.verify(jades, alg as Algorithm, certs[0].publicKey.export({ format: "pem", type: "pkcs1" }).toString("ascii"))).to.equal(true);
						});
					});
				});

			});
		});

	});

	describe("ES", () => {

		["256", "384", "521"].forEach(keyLength => {
			describe("Key length: " + keyLength, () => {

				["ES256", "ES384", "ES512"].forEach(alg => {

					const key = createPrivateKey({
						key: fs.readFileSync(__dirname + "/test_elliptic_" + keyLength + ".pem", "ascii"),
						format: "pem",
						type: "pkcs1"
					});
					const certs = parseCerts(fs.readFileSync(__dirname + "/test_elliptic_" + keyLength + ".crt", "ascii"));

					describe(alg, () => {

						const token = new Token(payload);
						token.setProtectedHeaders(new ProtectedHeaders({
							x5c: generateX5c(certs)
						}));

						if (alg.slice(2) !== keyLength && !(alg === "ES512" && keyLength === "521")) {
							it("should throw an error if the key is not valid for the given algorithm", () => {
								expect(() => token.sign(alg as SignAlg, key)).to.throw(TypeError);
							});

							return
						}

						token.sign(alg as SignAlg, key);
						const jades = token.toString();

						it("should return a string", () => {
							expect(jades).to.be.a("string");
						});
						it("should be a valid JWS", () => {
							expect(jades.split(".").length).to.equal(3);
						});
						it("signature lenght should be correct", () => {
							expect(Buffer.from(jades.split(".")[2], "base64").toString("hex").length).to.equal({
								"ES256": 64 * 2,
								"ES384": 96 * 2,
								"ES512": 132 * 2
							}[alg]);
						});
						it("should be a valid JWS with a valid header", () => {
							expect(JSON.parse(Buffer.from(jades.split(".")[0], "base64").toString("utf8"))).to.be.an("object");
						});

						// validate with jose
						it("should be a valid JWS (JOSE)", async () => {
							const { payload: _payload/*, protectedHeaders */ } = await jose.compactVerify(jades, certs[0].publicKey);
							const returnedString = Buffer.from(_payload).toString("utf8");
							expect(returnedString).to.equal(JSON.stringify(payload));
						});

						// validate with jws
						it("should be a valid JWS (JWS)", () => {
							expect(jws.verify(jades, alg as Algorithm, certs[0].publicKey.export({ format: "pem", type: "spki" }).toString("ascii"))).to.equal(true);
						});
					});
				});

			});
		});

	});

});

/*
let token = sign(payload, options);
console.log(token);


(async () => {
	console.log(certs[0].publicKey);

	const { payload, protectedHeaders } = await jose.compactVerify(token, certs[0].publicKey);

	console.log(payload.toString("utf8"), protectedHeaders)

	console.log(jws.verify(token, "RS512", certs[0].publicKey));
})()
*/
