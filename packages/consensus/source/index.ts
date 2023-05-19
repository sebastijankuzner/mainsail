import { Contracts, Identifiers } from "@mainsail/contracts";
import { Providers } from "@mainsail/kernel";

import { Broadcaster } from "./broadcaster";
import { Consensus } from "./consensus";
import { MessageFactory } from "./factory";
import { Handler } from "./handler";
import { RoundStateRepository } from "./round-state-repository";
import { Scheduler } from "./scheduler";
import { Serializer } from "./serializer";
import { Validator } from "./validator";
import { ValidatorRepository } from "./validator-repository";
import { ValidatorSet } from "./validator-set";
import { Verifier } from "./verifier";

export class ServiceProvider extends Providers.ServiceProvider {
	public async register(): Promise<void> {
		const keyPairFactory = this.app.get<Contracts.Crypto.IKeyPairFactory>(
			Identifiers.Consensus.Identity.KeyPairFactory,
		);

		this.app.bind(Identifiers.Consensus.Serializer).to(Serializer).inSingletonScope();
		this.app.bind(Identifiers.Consensus.MessageFactory).to(MessageFactory).inSingletonScope();
		this.app.bind(Identifiers.Consensus.Verifier).to(Verifier).inSingletonScope();

		const keyPairs = await Promise.all(
			this.app
				.config("validators.secrets")
				.map(async (mnemonic: string) => await keyPairFactory.fromMnemonic(mnemonic)),
		);
		const validators = keyPairs.map((keyPair) => this.app.resolve<Validator>(Validator).configure(keyPair));

		this.app.bind(Identifiers.Consensus.Handler).to(Handler).inSingletonScope();
		this.app.bind(Identifiers.Consensus.Broadcaster).to(Broadcaster).inSingletonScope();
		this.app.bind(Identifiers.Consensus.RoundStateRepository).to(RoundStateRepository).inSingletonScope();
		this.app.bind(Identifiers.Consensus.Scheduler).to(Scheduler).inSingletonScope();
		this.app.bind(Identifiers.Consensus.ValidatorSet).to(ValidatorSet).inSingletonScope();

		this.app
			.bind(Identifiers.Consensus.ValidatorRepository)
			.toConstantValue(this.app.resolve(ValidatorRepository).configure(validators));

		this.app.bind(Identifiers.Consensus.Service).toConstantValue(await this.app.resolve(Consensus).configure());
	}

	public async boot(): Promise<void> {
		void this.app.get<Consensus>(Identifiers.Consensus.Service).run();
	}
}
