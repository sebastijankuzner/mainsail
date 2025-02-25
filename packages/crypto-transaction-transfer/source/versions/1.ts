import { inject, injectable } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import { extendSchema, Transaction, transactionBaseSchema } from "@mainsail/crypto-transaction";
import { Utils } from "@mainsail/kernel";
import { BigNumber, ByteBuffer } from "@mainsail/utils";

@injectable()
export class TransferTransaction extends Transaction {
	@inject(Identifiers.Cryptography.Identity.Address.Serializer)
	private readonly addressSerializer!: Contracts.Crypto.AddressSerializer;

	@inject(Identifiers.Cryptography.Identity.Address.Size)
	private readonly addressSize!: number;

	public static typeGroup: number = Contracts.Crypto.TransactionTypeGroup.Core;
	public static type: number = Contracts.Crypto.TransactionType.Transfer;
	public static key = "transfer";

	public static getSchema(): Contracts.Crypto.TransactionSchema {
		return extendSchema(transactionBaseSchema, {
			$id: "transfer",
			properties: {
				amount: { bignumber: { maximum: undefined, minimum: 1 } },
				expiration: { minimum: 0, type: "integer" },
				recipientId: { $ref: "address" },
				type: { transactionType: Contracts.Crypto.TransactionType.Transfer },
				vendorField: { anyOf: [{ type: "null" }, { format: "vendorField", type: "string" }] },
			},
			required: ["recipientId"],
		});
	}

	public hasVendorField(): boolean {
		return true;
	}

	public assetSize(): number {
		return (
			32 + // amount
			4 + // expiration
			this.addressSize // recipient
		);
	}

	public async serialize(options?: Contracts.Crypto.SerializeOptions): Promise<ByteBuffer> {
		const { data } = this;
		const buff: ByteBuffer = ByteBuffer.fromSize(this.assetSize());
		buff.writeUint256(data.amount.toBigInt());
		buff.writeUint32(data.expiration || 0);

		Utils.assert.defined<string>(data.recipientId);

		this.addressSerializer.serialize(buff, await this.addressFactory.toBuffer(data.recipientId));

		return buff;
	}

	public async deserialize(buf: ByteBuffer): Promise<void> {
		const { data } = this;
		data.amount = BigNumber.make(buf.readUint256());
		data.expiration = buf.readUint32();
		data.recipientId = await this.addressFactory.fromBuffer(this.addressSerializer.deserialize(buf));
	}
}
