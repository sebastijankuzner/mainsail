import { inject, injectable, postConstruct } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import { BigNumber } from "@mainsail/utils";
import { Evm } from "@mainsail/evm";

@injectable()
export class EvmInstance implements Contracts.Evm.Instance {
	@inject(Identifiers.Application.Instance)
	protected readonly app!: Contracts.Kernel.Application;

	#evm!: Evm;

	@postConstruct()
	public initialize() {
		this.#evm = new Evm(this.app.dataPath());
	}

	public async prepareNextCommit(context: Contracts.Evm.PrepareNextCommitContext): Promise<void> {
		return this.#evm.prepareNextCommit(context);
	}

	public async view(viewContext: Contracts.Evm.TransactionViewContext): Promise<Contracts.Evm.ViewResult> {
		return this.#evm.view(viewContext);
	}

	public async process(txContext: Contracts.Evm.TransactionContext): Promise<Contracts.Evm.ProcessResult> {
		return this.#evm.process(txContext);
	}

	public async initializeGenesis(commit: Contracts.Evm.GenesisInfo): Promise<void> {
		return this.#evm.initializeGenesis({
			account: commit.account,
			initialSupply: commit.initialSupply,
			deployerAccount: commit.deployerAccount,
			validatorContract: commit.validatorContract,
		});
	}

	public async getAccountInfo(address: string): Promise<Contracts.Evm.AccountInfo> {
		return this.#evm.getAccountInfo(address);
	}

	public async updateRewardsAndVotes(context: Contracts.Evm.UpdateRewardsAndVotesContext): Promise<void> {
		return this.#evm.updateRewardsAndVotes(context);
	}

	public async calculateTopValidators(context: Contracts.Evm.CalculateTopValidatorsContext): Promise<void> {
		return this.#evm.calculateTopValidators(context);
	}

	public async onCommit(unit: Contracts.Processor.ProcessableUnit): Promise<void> {
		const { height } = unit;
		const round = unit.getBlock().data.round;
		const result = await this.#evm.commit({ height: BigInt(height), round: BigInt(round) });

		if (unit.store) {
			const walletRepository = unit.store.walletRepository;
			for (const account of result.dirtyAccounts) {
				const wallet = walletRepository.findByAddress(account.address);
				wallet.setBalance(BigNumber.make(account.balance));
				wallet.setNonce(BigNumber.make(account.nonce));

				if (account.vote) {
					const votedWallet = walletRepository.findByAddress(account.vote);
					wallet.setAttribute("vote", votedWallet.getPublicKey());
				} else if (account.unvote) {
					wallet.forgetAttribute("vote");
				}
			}
		}
	}

	public async codeAt(address: string): Promise<string> {
		return this.#evm.codeAt(address);
	}

	public async storageAt(address: string, slot: bigint): Promise<string> {
		return this.#evm.storageAt(address, slot);
	}

	public async stateHash(commitKey: Contracts.Evm.CommitKey, currentHash: string): Promise<string> {
		return this.#evm.stateHash(commitKey, currentHash);
	}

	public mode(): Contracts.Evm.EvmMode {
		return Contracts.Evm.EvmMode.Persistent;
	}
}
