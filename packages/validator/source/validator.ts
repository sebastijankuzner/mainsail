import { inject, injectable, tagged } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import { Identifiers as EvmConsensusIdentifiers } from "@mainsail/evm-consensus";
import { Providers, Utils } from "@mainsail/kernel";
import { BigNumber } from "@mainsail/utils";
import { performance } from "perf_hooks";

@injectable()
export class Validator implements Contracts.Validator.Validator {
	@inject(Identifiers.ServiceProvider.Configuration)
	@tagged("plugin", "validator")
	private readonly configuration!: Providers.PluginConfiguration;

	@inject(EvmConsensusIdentifiers.Internal.GenesisInfo)
	private readonly genesisInfo!: Contracts.Evm.GenesisInfo;

	@inject(Identifiers.Cryptography.Block.Factory)
	private readonly blockFactory!: Contracts.Crypto.BlockFactory;

	@inject(Identifiers.Cryptography.Message.Serializer)
	private readonly messageSerializer!: Contracts.Crypto.MessageSerializer;

	@inject(Identifiers.Cryptography.Hash.Factory)
	private readonly hashFactory!: Contracts.Crypto.HashFactory;

	@inject(Identifiers.Cryptography.Configuration)
	private readonly cryptoConfiguration!: Contracts.Crypto.Configuration;

	@inject(Identifiers.Cryptography.Message.Factory)
	private readonly messagesFactory!: Contracts.Crypto.MessageFactory;

	@inject(Identifiers.State.Service)
	protected readonly stateService!: Contracts.State.Service;

	@inject(Identifiers.Transaction.Validator.Factory)
	private readonly createTransactionValidator!: Contracts.Transactions.TransactionValidatorFactory;

	@inject(Identifiers.Cryptography.Transaction.Factory)
	private readonly transactionFactory!: Contracts.Crypto.TransactionFactory;

	@inject(Identifiers.Services.Log.Service)
	private readonly logger!: Contracts.Kernel.Logger;

	@inject(Identifiers.TransactionPool.Worker)
	private readonly txPoolWorker!: Contracts.TransactionPool.Worker;

	#keyPair!: Contracts.Validator.ValidatorKeyPair;

	public configure(keyPair: Contracts.Validator.ValidatorKeyPair): Contracts.Validator.Validator {
		this.#keyPair = keyPair;

		return this;
	}

	public getConsensusPublicKey(): string {
		return this.#keyPair.publicKey;
	}

	public async prepareBlock(
		generatorAddress: string,
		round: number,
		timestamp: number,
	): Promise<Contracts.Crypto.Block> {
		const previousBlock = this.stateService.getStore().getLastBlock();
		const height = previousBlock.header.height + 1;

		const { stateHash, transactions } = await this.#getTransactionsForForging(generatorAddress, timestamp, {
			height: BigInt(height),
			round: BigInt(round),
		});
		return this.#makeBlock(round, generatorAddress, stateHash, transactions, timestamp);
	}

	public async propose(
		validatorIndex: number,
		round: number,
		validRound: number | undefined,
		block: Contracts.Crypto.Block,
		lockProof?: Contracts.Crypto.AggregatedSignature,
	): Promise<Contracts.Crypto.Proposal> {
		const serializedProposedBlock = await this.messageSerializer.serializeProposed({ block, lockProof });
		return this.messagesFactory.makeProposal(
			{
				data: { serialized: serializedProposedBlock.toString("hex") },
				round,
				validRound,
				validatorIndex,
			},
			await this.#keyPair.getKeyPair(),
		);
	}

	public async prevote(
		validatorIndex: number,
		height: number,
		round: number,
		blockId: string | undefined,
	): Promise<Contracts.Crypto.Prevote> {
		return this.messagesFactory.makePrevote(
			{
				blockId,
				height,
				round,
				type: Contracts.Crypto.MessageType.Prevote,
				validatorIndex,
			},
			await this.#keyPair.getKeyPair(),
		);
	}

	public async precommit(
		validatorIndex: number,
		height: number,
		round: number,
		blockId: string | undefined,
	): Promise<Contracts.Crypto.Precommit> {
		return this.messagesFactory.makePrecommit(
			{
				blockId,
				height,
				round,
				type: Contracts.Crypto.MessageType.Precommit,
				validatorIndex,
			},
			await this.#keyPair.getKeyPair(),
		);
	}

	async #getTransactionsForForging(
		generatorAddress: string,
		timestamp: number,
		commitKey: Contracts.Evm.CommitKey,
	): Promise<{ stateHash: string; transactions: Contracts.Crypto.Transaction[] }> {
		const transactionBytes = await this.txPoolWorker.getTransactionBytes();

		const validator = this.createTransactionValidator();
		await validator.getEvm().initializeGenesis(this.genesisInfo);
		await validator.getEvm().prepareNextCommit({ commitKey });

		const candidateTransactions: Contracts.Crypto.Transaction[] = [];
		const failedTransactions: Contracts.Crypto.Transaction[] = [];

		const previousBlock = this.stateService.getStore().getLastBlock();
		const milestone = this.cryptoConfiguration.getMilestone();
		let gasLeft = milestone.block.maxGasLimit;

		// txCollatorFactor% of the time for block preparation, the rest is for  block and proposal serialization and signing
		const timeLimit =
			performance.now() +
			milestone.timeouts.blockPrepareTime * this.configuration.getRequired<number>("txCollatorFactor");

		for (const bytes of transactionBytes) {
			if (performance.now() > timeLimit) {
				break;
			}

			const transaction = await this.transactionFactory.fromBytes(bytes);
			transaction.data.sequence = candidateTransactions.length;

			if (failedTransactions.some((t) => t.data.senderPublicKey === transaction.data.senderPublicKey)) {
				continue;
			}

			try {
				const gasLimit = transaction.data.asset?.evmCall?.gasLimit || 0;

				if (gasLeft - gasLimit < 0) {
					break;
				}

				const result = await validator.validate(
					{ commitKey, gasLimit: milestone.block.maxGasLimit, generatorAddress, timestamp },
					transaction,
				);

				gasLeft -= result.gasUsed;

				transaction.data.gasUsed = result.gasUsed;
				candidateTransactions.push(transaction);
			} catch (error) {
				this.logger.warning(`${transaction.id} failed to collate: ${error.message}`);
				failedTransactions.push(transaction);
			}
		}

		this.txPoolWorker.setFailedTransactions(failedTransactions);

		await validator.getEvm().updateRewardsAndVotes({
			commitKey,
			timestamp: BigInt(timestamp),
			validatorAddress: generatorAddress,
			blockReward: Utils.BigNumber.make(milestone.reward).toBigInt(),
			specId: milestone.evmSpec,
		});

		if(Utils.roundCalculator.isNewRound(previousBlock.header.height + 2, this.cryptoConfiguration)) {
			const { activeValidators } = this.cryptoConfiguration.getMilestone(previousBlock.header.height + 2);

			await validator.getEvm().calculateTopValidators({
				activeValidators: Utils.BigNumber.make(activeValidators).toBigInt(),
				commitKey,
				specId: milestone.evmSpec,
				timestamp: BigInt(timestamp),
				validatorAddress: generatorAddress,
			});
		}

		return {
			stateHash: await validator.getEvm().stateHash(commitKey, previousBlock.header.stateHash),
			transactions: candidateTransactions,
		};
	}

	async #makeBlock(
		round: number,
		generatorPublicKey: string,
		stateHash: string,
		transactions: Contracts.Crypto.Transaction[],
		timestamp: number,
	): Promise<Contracts.Crypto.Block> {
		const totals: { amount: BigNumber; fee: BigNumber; gasUsed: number } = {
			amount: BigNumber.ZERO,
			fee: BigNumber.ZERO,
			gasUsed: 0,
		};

		const previousBlock = this.stateService.getStore().getLastBlock();
		const height = previousBlock.header.height + 1;
		const milestone = this.cryptoConfiguration.getMilestone(height);

		const payloadBuffers: Buffer[] = [];
		const transactionData: Contracts.Crypto.TransactionData[] = [];

		// The payload length needs to account for the overhead of each serialized transaction
		// which is a uint16 per transaction to store the individual length.
		let payloadLength = transactions.length * 2;

		for (const transaction of transactions) {
			const { data, serialized } = transaction;
			Utils.assert.defined<string>(data.id);
			Utils.assert.defined<number>(data.gasUsed);

			totals.amount = totals.amount.plus(data.amount);
			totals.fee = totals.fee.plus(data.fee);
			totals.gasUsed += data.gasUsed;

			payloadBuffers.push(Buffer.from(data.id, "hex"));
			transactionData.push(data);
			payloadLength += serialized.length;
		}

		return this.blockFactory.make(
			{
				generatorPublicKey,
				height,
				numberOfTransactions: transactionData.length,
				payloadHash: (await this.hashFactory.sha256(payloadBuffers)).toString("hex"),
				payloadLength,
				previousBlock: previousBlock.header.id,
				reward: BigNumber.make(milestone.reward),
				round,
				stateHash,
				timestamp,
				totalAmount: totals.amount,
				totalFee: totals.fee,
				totalGasUsed: totals.gasUsed,
				transactions: transactionData,
				version: 1,
			},
			transactions,
		);
	}
}
