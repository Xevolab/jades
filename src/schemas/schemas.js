/*
 * Author    : Francesco
 * Created at: 2023-08-01 10:12
 * Edited by : Francesco
 * Edited at : 2024-06-29 21:27
 *
 * Copyright (c) 2023-2024 Xevolab S.R.L.
 */

// Import necessary modules
const Ajv = require("ajv");
const addFormats = require("ajv-formats");
const fs = require("fs");

// Initialize AJV with options
const ajv = new Ajv({
	allErrors: true, // Show all errors, not just the first
	strict: false, // Disable strict mode for schema validation
});

// Add standard formats
addFormats(ajv);

// Function to read and add schema from a file
function addSchemaFromFile(schemaId, filePath) {
	const schema = JSON.parse(fs.readFileSync(filePath, "utf-8"));
	ajv.addSchema({ $id: schemaId, ...schema });
}

// Add schemas
addSchemaFromFile("19182-jsonSchema.json", `${__dirname}/19182-jsonSchema.json`);
addSchemaFromFile("19182-protected-jsonSchema.json", `${__dirname}/19182-protected-jsonSchema.json`);
addSchemaFromFile("19182-unprotected-jsonSchema.json", `${__dirname}/19182-unprotected-jsonSchema.json`);
addSchemaFromFile("rfcs/rfc7515.json", `${__dirname}/rfcs/rfc7515.json`);
addSchemaFromFile("rfcs/rfc7517.json", `${__dirname}/rfcs/rfc7517.json`);
addSchemaFromFile("rfcs/rfc7797.json", `${__dirname}/rfcs/rfc7797.json`);

// Export validation functions
exports.validateProtected = ajv.getSchema("19182-protected-jsonSchema.json");
exports.validateUnprotected = ajv.getSchema("19182-unprotected-jsonSchema.json");
