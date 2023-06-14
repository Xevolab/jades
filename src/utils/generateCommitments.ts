/*
 * Author    : Francesco
 * Created at: 2023-06-14 13:50
 * Edited by :
 * Edited at :
 *
 * Copyright (c) 2023 Xevolab S.R.L.
 */

interface Commitment {
	[key: string]: [string, string];
}
const commitments: Commitment = {
	proofOfOrigin: ["http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin", "It indicates that the signer recognizes to have created, approved and sent the signed data."],
	proofOfReceipt: ["http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt", "It indicates that signer recognizes to have received the content of the signed data."],
	proofOfDelivery: ["http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery", "It indicates that the TSP providing that indication has delivered a signed data in a local store accessible to the recipient of the signed data."],
	proofOfSender: ["http://uri.etsi.org/01903/v1.2.2#ProofOfSender", "It indicates that the entity providing that indication has sent the signed data (but not necessarily created it)."],
	proofOfApproval: ["http://uri.etsi.org/01903/v1.2.2#ProofOfApproval", "It indicates that the signer has approved the content of the signed data."],
	proofOfCreation: ["http://uri.etsi.org/01903/v1.2.2#ProofOfCreation", "It indicates that the signer has created the signed data (but not necessarily approved, nor sent it)."]
};

/** */
export default function generateCommitments(c: {
	proofOfOrigin?: boolean,
	proofOfReceipt?: boolean,
	proofOfDelivery?: boolean,
	proofOfSender?: boolean,
	proofOfApproval?: boolean,
	proofOfCreation?: boolean,
}) {

	return Object.keys(c).filter((key: string) => commitments[key]).map((key) => ({
		commId: {
			id: commitments[key][0],
			desc: commitments[key][1],
		}
	}));

}
