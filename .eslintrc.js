/*
 * Author    : Francesco
 * Created at: 2023-06-13 21:23
 * Edited by : Francesco
 * Edited at : 2023-06-13 22:12
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

module.exports = {
	env: {
		node: true,
		commonjs: true,
		es2021: true
	},
	extends: "airbnb-base",
	overrides: [],
	parserOptions: {
		ecmaVersion: "latest",
		sourceType: "module"
	},
	rules: {
		quotes: "off",
		"comma-dangle": "off",
		indent: ["error", "tab", { SwitchCase: 1 }],
		"no-tabs": 0,
		"padded-blocks": "off",
		"object-curly-newline": "off",
		"no-multiple-empty-lines": ["error", { max: 2, maxBOF: 0, maxEOF: 0 }],
		"nonblock-statement-body-position": "off",
		curly: ["error", "multi-or-nest", "consistent"],
	}
};
