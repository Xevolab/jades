"use strict";
/*
 * Author    : Francesco
 * Created at: 2023-06-13 21:24
 * Edited by : Francesco
 * Edited at : 2023-06-13 22:14
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateUnprotected = exports.validateProtected = void 0;
const ajv_1 = __importDefault(require("ajv"));
const ajv_formats_1 = __importDefault(require("ajv-formats"));
const fs_1 = __importDefault(require("fs"));
const ajv = new ajv_1.default({
    allErrors: true,
    strict: false,
});
(0, ajv_formats_1.default)(ajv);
ajv.addSchema(Object.assign({ $id: "19182-jsonSchema.json" }, JSON.parse(fs_1.default.readFileSync(`${__dirname}/19182-jsonSchema.json`, "utf-8"))));
ajv.addSchema(Object.assign({ $id: "19182-protected-jsonSchema.json" }, JSON.parse(fs_1.default.readFileSync(`${__dirname}/19182-protected-jsonSchema.json`, "utf-8"))));
ajv.addSchema(Object.assign({ $id: "19182-unprotected-jsonSchema.json" }, JSON.parse(fs_1.default.readFileSync(`${__dirname}/19182-unprotected-jsonSchema.json`, "utf-8"))));
ajv.addSchema(Object.assign({ $id: "rfcs/rfc7515.json" }, JSON.parse(fs_1.default.readFileSync(`${__dirname}/rfcs/rfc7515.json`, "utf-8"))));
ajv.addSchema(Object.assign({ $id: "rfcs/rfc7517.json" }, JSON.parse(fs_1.default.readFileSync(`${__dirname}/rfcs/rfc7517.json`, "utf-8"))));
ajv.addSchema(Object.assign({ $id: "rfcs/rfc7797.json" }, JSON.parse(fs_1.default.readFileSync(`${__dirname}/rfcs/rfc7797.json`, "utf-8"))));
exports.validateProtected = ajv.getSchema("19182-protected-jsonSchema.json");
exports.validateUnprotected = ajv.getSchema("19182-unprotected-jsonSchema.json");
