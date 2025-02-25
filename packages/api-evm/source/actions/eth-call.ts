import { inject, injectable, tagged } from "@mainsail/container";
import { Contracts, Exceptions, Identifiers } from "@mainsail/contracts";
import { ethers } from "ethers";

type BlockTag = "latest" | "finalized" | "safe";

type TxData = {
	from: string;
	to: string;
	data: string;
};

@injectable()
export class CallAction implements Contracts.Api.RPC.Action {
	@inject(Identifiers.Evm.Instance)
	@tagged("instance", "evm")
	private readonly evm!: Contracts.Evm.Instance;

	public readonly name: string = "eth_call";

	public readonly schema = {
		$id: `jsonRpc_${this.name}`,

		maxItems: 2,
		minItems: 2,

		prefixItems: [
			{
				additionalProperties: false,
				properties: {
					data: { $ref: "prefixedHex" },
					from: { $ref: "address" },
					to: { $ref: "address" },
				},
				required: ["from", "to", "data"],
				type: "object",
			},
			{ enum: ["latest", "finalized", "safe"], type: "string" },
		],

		type: "array",
	};

	public async handle(parameters: [TxData, BlockTag]): Promise<any> {
		const [data] = parameters;

		const { success, output } = await this.evm.view({
			caller: data.from,
			data: Buffer.from(ethers.getBytes(data.data)),
			recipient: data.to,
			specId: Contracts.Evm.SpecId.LATEST,
		});

		if (success) {
			return `0x${output?.toString("hex")}`;
		}

		throw new Exceptions.RpcError("execution reverted");
	}
}
