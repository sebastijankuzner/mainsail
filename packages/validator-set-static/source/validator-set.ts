import { inject, injectable } from "@mainsail/container";
import { Contracts, Exceptions, Identifiers } from "@mainsail/contracts";
import { Utils } from "@mainsail/kernel";

@injectable()
export class ValidatorSet implements Contracts.ValidatorSet.Service {
	@inject(Identifiers.Cryptography.Configuration)
	private readonly configuration!: Contracts.Crypto.Configuration;

	@inject(Identifiers.State.ValidatorWallet.Factory)
	private readonly validatorWalletFactory!: Contracts.State.ValidatorWalletFactory;

	#validators: Contracts.State.ValidatorWallet[] = [];
	#indexByWalletPublicKey: Map<string, number> = new Map();

	public async restore(store: Contracts.State.Store): Promise<void> {
		this.#buildActiveValidators(store);
	}

	public async onCommit(unit: Contracts.Processor.ProcessableUnit): Promise<void> {
		if (Utils.roundCalculator.isNewRound(unit.height + 1, this.configuration)) {
			this.#buildActiveValidators(unit.store);
		}
	}

	public getActiveValidators(): Contracts.State.ValidatorWallet[] {
		const { activeValidators } = this.configuration.getMilestone();

		if (this.#validators.length !== activeValidators) {
			throw new Exceptions.NotEnoughActiveValidatorsError(this.#validators.length, activeValidators);
		}

		return this.#validators;
	}

	public getValidator(index: number): Contracts.State.ValidatorWallet {
		return this.#validators[index];
	}

	public getValidatorIndexByWalletAddress(walletPublicKey: string): number {
		const result = this.#indexByWalletPublicKey.get(walletPublicKey);

		if (result === undefined) {
			throw new Error(`Validator ${walletPublicKey} not found.`);
		}

		return result;
	}

	#buildActiveValidators(store: Contracts.State.Store): void {
		this.#validators = [];
		this.#indexByWalletPublicKey = new Map();

		const { activeValidators } = this.configuration.getMilestone();

		const validators = store.walletRepository.allValidators();

		for (let index = 0; index < activeValidators; index++) {
			const validator = this.validatorWalletFactory(validators[index]);

			validator.setRank(index + 1);

			// All static validators have equal approval
			validator.setApproval(100 / activeValidators);

			this.#validators.push(validator);

			const walletPublicKey = validator.getWallet().getAddress();
			Utils.assert.defined<string>(walletPublicKey);
			this.#indexByWalletPublicKey.set(walletPublicKey, index);
		}
	}
}
