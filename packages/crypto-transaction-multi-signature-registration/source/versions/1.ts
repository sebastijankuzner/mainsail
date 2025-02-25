import { inject, injectable, tagged } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import { extendSchema, Transaction, transactionBaseSchema } from "@mainsail/crypto-transaction";
import { Utils } from "@mainsail/kernel";
import { ByteBuffer } from "@mainsail/utils";

@injectable()
export class MultiSignatureRegistrationTransaction extends Transaction {
	@inject(Identifiers.Application.Instance)
	public readonly app!: Contracts.Kernel.Application;

	@inject(Identifiers.Cryptography.Identity.PublicKey.Serializer)
	@tagged("type", "wallet")
	private readonly publicKeySerializer!: Contracts.Crypto.PublicKeySerializer;

	@inject(Identifiers.Cryptography.Identity.PublicKey.Size)
	@tagged("type", "wallet")
	private readonly publicKeySize!: number;

	public static typeGroup: number = Contracts.Crypto.TransactionTypeGroup.Core;
	public static type: number = Contracts.Crypto.TransactionType.MultiSignature;
	public static key = "multiSignature";

	public static getSchema(): Contracts.Crypto.TransactionSchema {
		return extendSchema(transactionBaseSchema, {
			$id: "multiSignature",
			properties: {
				asset: {
					properties: {
						multiSignature: {
							properties: {
								min: {
									maximum: { $data: "1/publicKeys/length" },
									minimum: 1,
									type: "integer",
								},
								publicKeys: {
									items: { $ref: "publicKey" },
									maxItems: 16,
									minItems: 2,
									type: "array",
									uniqueItems: true,
								},
							},
							required: ["min", "publicKeys"],
							type: "object",
							unevaluatedProperties: false,
						},
					},
					required: ["multiSignature"],
					type: "object",
					unevaluatedProperties: false,
				},
				signatures: {
					items: { allOf: [{ maxLength: 130, minLength: 130 }, { $ref: "alphanumeric" }] },
					maxItems: { $data: "1/asset/multiSignature/publicKeys/length" },
					minItems: { $data: "1/asset/multiSignature/min" },
					type: "array",
					uniqueItems: true,
				},
				type: { transactionType: Contracts.Crypto.TransactionType.MultiSignature },
			},
			required: ["asset"],
		});
	}

	public assetSize(): number {
		const { data } = this;
		Utils.assert.defined<Contracts.Crypto.MultiSignatureAsset>(data.asset?.multiSignature);
		const { publicKeys } = data.asset.multiSignature;

		return (
			1 + // min
			1 + // number of public keys
			publicKeys.length * this.publicKeySize // public keys
		);
	}

	public async serialize(options?: Contracts.Crypto.SerializeOptions): Promise<ByteBuffer> {
		const { data } = this;
		Utils.assert.defined<Contracts.Crypto.MultiSignatureAsset>(data.asset?.multiSignature);
		const { min, publicKeys } = data.asset.multiSignature;
		const buff: ByteBuffer = ByteBuffer.fromSize(this.assetSize());

		buff.writeUint8(min);
		buff.writeUint8(publicKeys.length);

		for (const publicKey of publicKeys) {
			buff.writeBytes(Buffer.from(publicKey, "hex"));
		}

		return buff;
	}

	public async deserialize(buf: ByteBuffer): Promise<void> {
		const { data } = this;

		const multiSignature: Contracts.Crypto.MultiSignatureAsset = { min: 0, publicKeys: [] };
		multiSignature.min = buf.readUint8();

		const count = buf.readUint8();
		for (let index = 0; index < count; index++) {
			const publicKey = this.publicKeySerializer.deserialize(buf).toString("hex");
			multiSignature.publicKeys.push(publicKey);
		}

		data.asset = { multiSignature };
	}
}
