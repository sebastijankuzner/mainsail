import { inject, injectable, tagged } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import { Utils } from "@mainsail/kernel";
import { ethers, sha256 } from "ethers";

import { CONSENSUS } from "./contracts.ts/index.js";
import { Identifiers as EvmConsensusIdentifiers } from "./identifiers.js";

// TODO: extract "evm-deployer" package to manage nonce, etc. when deploying protocol contracts.
// Also see "evm-development" which this code is originally based on.

@injectable()
export class Deployer {
	@inject(Identifiers.Application.Instance)
	private readonly app!: Contracts.Kernel.Application;

	@inject(Identifiers.Cryptography.Configuration)
	private readonly configuration!: Contracts.Crypto.Configuration;

	@inject(Identifiers.Services.Log.Service)
	private readonly logger!: Contracts.Kernel.Logger;

	@inject(Identifiers.Evm.Instance)
	@tagged("instance", "evm")
	private readonly evm!: Contracts.Evm.Instance;

	// Deploy consensus contract (TODO: change to another address?)
	#deployerAddress = "0x0000000000000000000000000000000000000001";

	public async deploy(): Promise<void> {
		const genesisBlock = this.app.config<Contracts.Crypto.CommitJson>("crypto.genesisBlock");
		Utils.assert.defined(genesisBlock);

		const milestone = this.configuration.getMilestone(0);

		// Commit Key chosen in a way such that it does not conflict with blocks.
		const commitKey = { height: BigInt(2 ** 32 + 1), round: BigInt(0) };
		const blockContext = {
			commitKey,
			gasLimit: BigInt(milestone.block.maxGasLimit),
			timestamp: BigInt(genesisBlock.block.timestamp),
			validatorAddress: this.#deployerAddress,
		};

		const result = await this.evm.process({
			blockContext,
			caller: this.#deployerAddress,
			data: Buffer.from(ethers.getBytes(CONSENSUS.abi.bytecode)),
			gasLimit: BigInt(10_000_000),
			specId: milestone.evmSpec,
			txHash: this.#generateTxHash(),
		});

		if (!result.receipt.success) {
			throw new Error("failed to deploy Consensus contract");
		}

		this.logger.info(
			`Deployed Consensus contract from ${this.#deployerAddress} to ${result.receipt.deployedContractAddress}`,
		);

		this.app
			.bind(EvmConsensusIdentifiers.Contracts.Addresses.Consensus)
			.toConstantValue(result.receipt.deployedContractAddress!);

		await this.evm.onCommit(commitKey as any);
	}

	// TODO: update votes
	// TODO: update sort

	#nonce = 0;
	#generateTxHash = () => sha256(Buffer.from(`deployertx-${this.#nonce++}`, "utf8")).slice(2);
}
