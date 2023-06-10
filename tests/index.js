/*
 * Author    : Francesco
 * Created at: 2023-06-02 13:45
 * Edited by : Francesco
 * Edited at : 2023-06-09 18:36
 * 
 * Copyright (c) 2023 Xevolab S.R.L.
 */

const { sign } = require("../dist/index.js");

const fs = require("fs");

(async () => {
	const payload = {
		"aud": "https://server.example.com",
		"exp": 1300819380,
	};

	const options = {
		serialization: "compact",
		alg: "RS512",

		key: fs.readFileSync("xevolab.key", "ascii"),
		cert: fs.readFileSync("xevolab.pem", "ascii"),

		signedHeaders: {
			autoIncludeKid: true,
			autoIncludeX5c: true,
			autoIncludeX5cO: false
		}
	};

	console.log(sign(payload, options))

})()
