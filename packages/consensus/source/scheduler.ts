import { inject, injectable } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import delay from "delay";

import { IScheduler } from "./types";

@injectable()
export class Scheduler implements IScheduler {
	@inject(Identifiers.Application)
	private readonly app!: Contracts.Kernel.Application;

	@inject(Identifiers.Cryptography.Configuration)
	private readonly cryptoConfiguration!: Contracts.Crypto.IConfiguration;

	public async scheduleTimeoutPropose(height: number, round: number): Promise<void> {
		await this.#wait(round);
		await this.#getConsensus().onTimeoutPropose(height, round);
	}

	public async scheduleTimeoutPrevote(height: number, round: number): Promise<void> {
		await this.#wait(round);
		await this.#getConsensus().onTimeoutPrevote(height, round);
	}

	public async scheduleTimeoutPrecommit(height: number, round: number): Promise<void> {
		await this.#wait(round);
		await this.#getConsensus().onTimeoutPrecommit(height, round);
	}

	async #wait(round: number) {
		await delay(
			this.cryptoConfiguration.getMilestone().stageTimeout +
				round * this.cryptoConfiguration.getMilestone().stageTimeoutIncrease,
		);
	}

	#getConsensus(): Contracts.Consensus.IConsensusService {
		return this.app.get<Contracts.Consensus.IConsensusService>(Identifiers.Consensus.Service);
	}
}
