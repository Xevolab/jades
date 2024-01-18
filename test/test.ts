/*
 * Author    : Francesco
 * Created at: 2023-09-24 09:53
 * Edited by : Francesco
 * Edited at : 2024-01-18 11:31
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { describe, it } from "node:test";
import { expect } from "chai";

import { createPrivateKey } from "crypto";
import * as fs from "fs";

import * as jose from "jose";
import * as jws from "jws";
import sign, { parseCerts, generateX5c, SignAlg } from "../src/index";

import { Algorithm } from "jws";

const payload = {
	content: true
}

console.log(__dirname);

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
						const options = {
							serialization: "compact" as const,
							detached: false,

							key,
							alg: alg as SignAlg,

							protectedHeaders: {
								x5c: generateX5c(certs),
								sigT: null
							},
						};

						const token = sign(payload, options) as string;

						it("should return a string", () => {
							expect(token).to.be.a("string");
						});
						it("should be a valid JWS", () => {
							expect(token.split(".").length).to.equal(3);
						});
						it("should be a valid JWS with a valid header", () => {
							expect(JSON.parse(Buffer.from(token.split(".")[0], "base64").toString("utf8"))).to.be.an("object");
						});
						it("signature lenght should be correct", () => {
							const sigLengthHex = Buffer.from(token.split(".")[2], "base64").toString("hex").length;

							// 2048 bits = 256 bytes = 512 hex chars
							expect(sigLengthHex).to.equal(parseInt(keyLength) / 4);
						});

						// validate with jose
						it("should be a valid JWS (JOSE)", async () => {
							const { payload: _payload/*, protectedHeaders */ } = await jose.compactVerify(token, certs[0].publicKey);

							expect(_payload.toString()).to.equal(JSON.stringify(payload));
						});

						// validate with jws
						it("should be a valid JWS (JWS)", () => {
							expect(jws.verify(token, alg as Algorithm, certs[0].publicKey.export({ format: "pem", type: "pkcs1" }).toString("ascii"))).to.equal(true);
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
						let options = {
							serialization: "compact" as const,
							detached: false,

							key,
							alg: alg as SignAlg,

							protectedHeaders: {
								x5c: generateX5c(certs),
								sigT: null
							},
						};

						if (alg.slice(2) !== keyLength && !(alg === "ES512" && keyLength === "521")) {
							it("should throw an error if the key is not valid for the given algorithm", () => {
								expect(() => sign(payload, options)).to.throw(TypeError);
							});

							return
						}

						const token = sign(payload, options) as string;

						it("should return a string", () => {
							expect(token).to.be.a("string");
						});
						it("should be a valid JWS", () => {
							expect(token.split(".").length).to.equal(3);
						});
						it("signature lenght should be correct", () => {
							expect(Buffer.from(token.split(".")[2], "base64").toString("hex").length).to.equal({
								"ES256": 64 * 2,
								"ES384": 96 * 2,
								"ES512": 132 * 2
							}[alg]);
						});
						it("should be a valid JWS with a valid header", () => {
							expect(JSON.parse(Buffer.from(token.split(".")[0], "base64").toString("utf8"))).to.be.an("object");
						});

						// validate with jose
						it("should be a valid JWS (JOSE)", async () => {
							const { payload: _payload/*, protectedHeaders */ } = await jose.compactVerify(token, certs[0].publicKey);
							expect(_payload.toString()).to.equal(JSON.stringify(payload));
						});

						// validate with jws
						it("should be a valid JWS (JWS)", () => {
							expect(jws.verify(token, alg as Algorithm, certs[0].publicKey.export({ format: "pem", type: "spki" }).toString("ascii"))).to.equal(true);
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
