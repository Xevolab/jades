/*
 * Author    : Francesco
 * Created at: 2023-06-02 13:45
 * Edited by : Francesco
 * Edited at : 2023-06-09 16:45
 * 
 * Copyright (c) 2023 Xevolab S.R.L.
 */

import { sign } from "../src/index.js";

import fs from "fs";

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
