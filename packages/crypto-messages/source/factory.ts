import { inject, injectable } from "@mainsail/container";
import { Contracts, Exceptions, Identifiers } from "@mainsail/contracts";
import { IpcWorker } from "@mainsail/kernel";
import { ByteBuffer } from "@mainsail/utils";

import { Precommit } from "./precommit.js";
import { Prevote } from "./prevote.js";
import { Proposal } from "./proposal.js";
import { performance } from "perf_hooks";

@injectable()
export class MessageFactory implements Contracts.Crypto.MessageFactory {
	@inject(Identifiers.Cryptography.Message.Serializer)
	private readonly serializer!: Contracts.Crypto.MessageSerializer;

	@inject(Identifiers.Cryptography.Message.Deserializer)
	private readonly deserializer!: Contracts.Crypto.MessageDeserializer;

	@inject(Identifiers.Cryptography.Block.Factory)
	private readonly blockFactory!: Contracts.Crypto.BlockFactory;

	@inject(Identifiers.Cryptography.Validator)
	private readonly validator!: Contracts.Crypto.Validator;

	@inject(Identifiers.CryptoWorker.WorkerPool)
	private readonly workerPool!: IpcWorker.WorkerPool;

	@inject(Identifiers.Services.Log.Service)
	protected readonly logger!: Contracts.Kernel.Logger;

	public async makeProposal(
		data: Contracts.Crypto.MakeProposalData,
		keyPair: Contracts.Crypto.KeyPair,
	): Promise<Contracts.Crypto.Proposal> {
		const worker = await this.workerPool.getWorker();

		const bytes = await this.serializer.serializeProposal(data, { includeSignature: false });
		const signature = await worker.consensusSignature("sign", bytes, Buffer.from(keyPair.privateKey, "hex"));
		const serialized = Buffer.concat([bytes, Buffer.from(signature, "hex")]);
		return this.makeProposalFromBytes(serialized);
	}

	public async makeProposalFromBytes(bytes: Buffer): Promise<Contracts.Crypto.Proposal> {
		const t1 = performance.now();

		const data = await this.deserializer.deserializeProposal(bytes);

		const t2 = performance.now();

		const res = await this.makeProposalFromData(data, bytes);

		this.logger.info(`!!!Processing proposal took ${performance.now() - t1}ms
!!!Deserializing proposal took ${t2 - t1}ms
!!!Making proposal from data took ${performance.now() - t2}ms
		`);

		return res;
	}

	public async makeProposalFromData(
		data: Contracts.Crypto.ProposalData,
		serialized?: Buffer,
	): Promise<Contracts.Crypto.Proposal> {
		const t1 = performance.now();
		this.#applySchema("proposal", data);

		const t2 = performance.now();

		const block = await this.#makeProposedBlockFromBytes(Buffer.from(data.block.serialized, "hex"));

		this.logger.info(`!!!Applying schema took ${t2 - t1}ms
!!!Making proposed block from bytes took ${performance.now() - t2}ms`);

		if (!serialized) {
			serialized = await this.serializer.serializeProposal(data, { includeSignature: true });
		}

		return new Proposal({ ...data, block, serialized });
	}

	public async makePrevote(
		data: Contracts.Crypto.MakePrevoteData,
		keyPair: Contracts.Crypto.KeyPair,
	): Promise<Contracts.Crypto.Prevote> {
		const worker = await this.workerPool.getWorker();

		const bytes = await this.serializer.serializePrevoteForSignature({
			blockId: data.blockId,
			height: data.height,
			round: data.round,
			type: data.type,
		});
		const signature = await worker.consensusSignature("sign", bytes, Buffer.from(keyPair.privateKey, "hex"));
		const serialized = await this.serializer.serializePrevote({ ...data, signature });
		return this.makePrevoteFromBytes(serialized);
	}

	public async makePrevoteFromBytes(bytes: Buffer): Promise<Contracts.Crypto.Precommit> {
		const data = await this.deserializer.deserializePrevote(bytes);
		return this.makePrevoteFromData(data, bytes);
	}

	public async makePrevoteFromData(
		data: Contracts.Crypto.PrevoteData,
		serialized?: Buffer,
	): Promise<Contracts.Crypto.Prevote> {
		this.#applySchema("prevote", data);

		if (!serialized) {
			serialized = await this.serializer.serializePrevote(data);
		}

		return new Prevote({ ...data, serialized });
	}

	public async makePrecommit(
		data: Contracts.Crypto.MakePrecommitData,
		keyPair: Contracts.Crypto.KeyPair,
	): Promise<Contracts.Crypto.Precommit> {
		const worker = await this.workerPool.getWorker();

		const bytes = await this.serializer.serializePrecommitForSignature({
			blockId: data.blockId,
			height: data.height,
			round: data.round,
			type: data.type,
		});
		const signature = await worker.consensusSignature("sign", bytes, Buffer.from(keyPair.privateKey, "hex"));

		const serialized = await this.serializer.serializePrecommit({ ...data, signature });
		return this.makePrecommitFromBytes(serialized);
	}

	public async makePrecommitFromBytes(bytes: Buffer): Promise<Contracts.Crypto.Precommit> {
		const data = await this.deserializer.deserializePrecommit(bytes);
		return this.makePrecommitFromData(data, bytes);
	}

	public async makePrecommitFromData(
		data: Contracts.Crypto.PrecommitData,
		serialized?: Buffer,
	): Promise<Contracts.Crypto.Precommit> {
		this.#applySchema("precommit", data);

		if (!serialized) {
			serialized = await this.serializer.serializePrecommit(data);
		}

		return new Precommit({ ...data, serialized });
	}

	async #makeProposedBlockFromBytes(bytes: Buffer): Promise<Contracts.Crypto.ProposedBlock> {
		const buffer = ByteBuffer.fromBuffer(bytes);

		const lockProofLength = buffer.readUint8();
		let lockProof: Contracts.Crypto.AggregatedSignature | undefined;
		if (lockProofLength > 0) {
			const lockProofBuffer = buffer.readBytes(lockProofLength);
			lockProof = await this.deserializer.deserializeLockProof(lockProofBuffer);
		}

		const block = await this.blockFactory.fromBytes(buffer.getRemainder());

		return {
			block,
			lockProof,
			serialized: bytes.toString("hex"),
		};
	}

	#applySchema<T>(schema: string, data: T): T {
		const result = this.validator.validate(schema, data);

		if (!result.error) {
			return result.value;
		}

		throw new Exceptions.MessageSchemaError(schema, result.error);
	}
}
