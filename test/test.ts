/*
 * Author    : Francesco
 * Created at: 2023-09-24 09:53
 * Edited by : Francesco
 * Edited at : 2023-11-29 16:39
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { describe, it } from "node:test";
import { expect } from "chai";

import { createPrivateKey } from "crypto";
import fs from "fs";

import * as jose from "jose";
import jws from "jws";
import sign, { parseCerts, generateX5c, SignAlg } from "../src/index";

const payload = { Bergamot: "for the win" };

import { Algorithm } from "jws";

describe("sign", () => {

	describe("RS", () => {

		const key = createPrivateKey({
			key: fs.readFileSync("test_rsa.pem", "ascii"),
			format: "pem",
			type: "pkcs1"
		});
		const certs = parseCerts(fs.readFileSync("test_rsa.crt", "ascii"));

		["RS256", "RS384", "RS512"].forEach(alg => {
			describe(alg, () => {
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

	describe("ES", () => {

		["ES256", "ES384", "ES512"].forEach(alg => {

			const key = createPrivateKey({
				key: fs.readFileSync("test_elliptic_" + alg + ".pem", "ascii"),
				format: "pem",
				type: "pkcs1"
			});
			const certs = parseCerts(fs.readFileSync("test_elliptic_" + alg + ".crt", "ascii"));

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

	})

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
