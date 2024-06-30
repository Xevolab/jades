/*
 * Author    : Francesco
 * Created at: 2023-06-02 13:35
 * Edited by : Francesco
 * Edited at : 2024-06-30 13:20
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

/**
 *  ! Please note that this is a draft and it's not ready for production. !
 *
 * This is a library that implements the ETSI TS 119 312 standard.
 * Please, consider visiting the official website for more information:
 * https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf
 *
 */

// Header classes
export { default as ProtectedHeaders } from "./classes/ProtectedHeaders";
export { default as UnprotectedHeaders } from "./classes/UnprotectedHeaders";
// Main class
export { default as Token } from "./classes/Token";

// Utils
export { default as parseCerts } from "./utils/parseCerts";
export { default as generateKid } from "./utils/generateKid";
export { generateX5c, generateX5ts, generateX5tS256, generateX5o } from "./utils/generateX5";
export { default as generateCommitments } from "./utils/generateCommitments";
