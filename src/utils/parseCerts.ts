/*
 * Author    : Francesco
 * Created at: 2024-06-30 13:19
 * Edited by : Francesco
 * Edited at : 2024-06-30 13:20
 *
 * Copyright (c) 2024 Xevolab S.R.L.
 */

import { X509Certificate } from "crypto";

export default function parseCerts(certs: string): X509Certificate[] {
	return certs.split("-----END CERTIFICATE-----").filter((j: string) => j.trim() !== "").map((j: string) => new X509Certificate(`${j}-----END CERTIFICATE-----`));
}
