export type SignAlg = "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512";

export interface ProtectedHeaders {
	kid?: null | string,
	x5u?: null | string,
	x5c?: null | string[],
	x5tS256?: null | string,
	x5tO?: null | { digAlg: string, digVal: string },
	sigX5ts?: null | { digAlg: string, digVal: string }[],
	srCms?: null | { commId: object }[],
	srAts?: null | object[],
	sigPl?: null | object,
	sigPId?: null | object,
	sigD?: null | object,
	adoTst?: null | object[]
}
