import { inject, injectable, tagged } from "@mainsail/container";
import { Contracts, Exceptions, Identifiers } from "@mainsail/contracts";
import { ByteBuffer } from "@mainsail/utils";

@injectable()
export class Serializer implements Contracts.Crypto.TransactionSerializer {
	@inject(Identifiers.Cryptography.Configuration)
	private readonly configuration!: Contracts.Crypto.Configuration;

	@inject(Identifiers.Cryptography.Transaction.TypeFactory)
	private readonly transactionTypeFactory!: Contracts.Transactions.TransactionTypeFactory;

	@inject(Identifiers.Cryptography.Identity.PublicKey.Size)
	@tagged("type", "wallet")
	private readonly publicKeySize!: number;

	@inject(Identifiers.Cryptography.Signature.Size)
	@tagged("type", "wallet")
	private readonly signatureSize!: number;

	public async getBytes(
		transaction: Contracts.Crypto.TransactionData,
		options: Contracts.Crypto.SerializeOptions = {},
	): Promise<Buffer> {
		const version: number = transaction.version || 1;

		if (version) {
			return this.serialize(this.transactionTypeFactory.create(transaction), options);
		}

		throw new Exceptions.TransactionVersionError(version);
	}

	public commonSize(transaction: Contracts.Crypto.Transaction): number {
		return (
			1 + // magic byte
			1 + // version
			1 + // network
			4 + // typeGroup
			2 + // type
			8 + // nonce
			(transaction.data.senderPublicKey ? this.publicKeySize : 0) + // sender public key
			32 // fee
		);
	}

	public vendorFieldSize(transaction: Contracts.Crypto.Transaction): number {
		let vendorFieldSize = 1; // length byte

		if (transaction.hasVendorField() && transaction.data.vendorField) {
			const vf: Buffer = Buffer.from(transaction.data.vendorField, "utf8");
			vendorFieldSize += vf.length;
		}

		return vendorFieldSize;
	}

	public signaturesSize(
		transaction: Contracts.Crypto.Transaction,
		options: Contracts.Crypto.SerializeOptions = {},
	): number {
		let size = 0;

		const { data } = transaction;
		if (data.signature && !options.excludeSignature) {
			size += this.signatureSize;
		}

		if (data.signatures && !options.excludeMultiSignature) {
			size += data.signatures.length * (1 + this.signatureSize) /* 1 additional byte for index */;
		}

		return size;
	}

	public totalSize(
		transaction: Contracts.Crypto.Transaction,
		options: Contracts.Crypto.SerializeOptions = {},
	): number {
		return (
			this.commonSize(transaction) +
			this.vendorFieldSize(transaction) +
			transaction.assetSize() +
			this.signaturesSize(transaction, options)
		);
	}

	public async serialize(
		transaction: Contracts.Crypto.Transaction,
		options: Contracts.Crypto.SerializeOptions = {},
	): Promise<Buffer> {
		const bufferSize = this.totalSize(transaction, options);
		const buff: ByteBuffer = ByteBuffer.fromSize(bufferSize);

		this.#serializeCommon(transaction.data, buff);
		this.#serializeVendorField(transaction, buff);

		const serialized: ByteBuffer | undefined = await transaction.serialize(options);

		if (!serialized) {
			throw new Error();
		}

		buff.writeBytes(serialized.getResult());

		this.#serializeSignatures(transaction.data, buff, options);

		const bufferBuffer = buff.getResult();
		if (bufferBuffer.length !== bufferSize) {
			throw new Exceptions.InvalidTransactionBytesError(
				`expected size ${bufferSize} actual size: ${bufferBuffer.length}`,
			);
		}

		transaction.serialized = bufferBuffer;

		return bufferBuffer;
	}

	#serializeCommon(transaction: Contracts.Crypto.TransactionData, buff: ByteBuffer): void {
		transaction.version = transaction.version || 0x01;
		if (transaction.typeGroup === undefined) {
			transaction.typeGroup = Contracts.Crypto.TransactionTypeGroup.Core;
		}

		buff.writeUint8(0xff);
		buff.writeUint8(transaction.version);
		buff.writeUint8(transaction.network || this.configuration.get("network.pubKeyHash"));
		buff.writeUint32(transaction.typeGroup);
		buff.writeUint16(transaction.type);
		buff.writeUint64(transaction.nonce.toBigInt());

		if (transaction.senderPublicKey) {
			buff.writeBytes(Buffer.from(transaction.senderPublicKey, "hex"));
		}

		buff.writeUint256(transaction.fee.toBigInt());
	}

	#serializeVendorField(transaction: Contracts.Crypto.Transaction, buff: ByteBuffer): void {
		const { data }: Contracts.Crypto.Transaction = transaction;

		if (transaction.hasVendorField() && data.vendorField) {
			const vf: Buffer = Buffer.from(data.vendorField, "utf8");
			buff.writeUint8(vf.length);
			buff.writeBytes(vf);
		} else {
			buff.writeUint8(0x00);
		}
	}

	#serializeSignatures(
		transaction: Contracts.Crypto.TransactionData,
		buff: ByteBuffer,
		options: Contracts.Crypto.SerializeOptions = {},
	): void {
		if (transaction.signature && !options.excludeSignature) {
			buff.writeBytes(Buffer.from(transaction.signature, "hex"));
		}

		if (transaction.signatures && !options.excludeMultiSignature) {
			buff.writeBytes(Buffer.from(transaction.signatures.join(""), "hex"));
		}
	}
}
