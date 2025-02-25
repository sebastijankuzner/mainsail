import { Contracts } from "@mainsail/contracts";
import { describe, Sandbox } from "@mainsail/test-framework";
import { EvmCalls, Utils } from "@mainsail/test-transaction-builders";
import { setup, shutdown } from "./setup.js";
import { Snapshot, takeSnapshot } from "./snapshot.js";
import { addTransactionsToPool, getWallets, isTransactionCommitted, waitBlock } from "./utils.js";
import { ethers } from "ethers";

describe<{
	sandbox: Sandbox;
	snapshot: Snapshot;
	wallets: Contracts.Crypto.KeyPair[];
}>("EVM Call", ({ beforeEach, afterEach, it, assert }) => {
	beforeEach(async (context) => {
		context.sandbox = await setup();
		context.wallets = await getWallets(context.sandbox);
		context.snapshot = await takeSnapshot(context.sandbox);
	});

	afterEach(async ({ sandbox, snapshot }) => {
		await snapshot.validate();

		await shutdown(sandbox);
	});

	it("should accept and commit evm call", async (context) => {
		const tx = await EvmCalls.makeEvmCall(context);

		const { accept } = await addTransactionsToPool(context, [tx]);
		assert.equal(accept, [0]);

		await waitBlock(context);
		await isTransactionCommitted(context, tx);
	});

	it("should deploy contract and interact with it", async (context) => {
		const deployTx = await EvmCalls.makeEvmCallDeployErc20Contract(context);

		let { accept } = await addTransactionsToPool(context, [deployTx]);
		assert.equal(accept, [0]);

		await waitBlock(context);
		await isTransactionCommitted(context, deployTx);

		const erc20Address = ethers.getCreateAddress({
			from: ethers.computeAddress(`0x${deployTx.data.senderPublicKey}`),
			nonce: 3,
		});

		// Successfully transfer tokens on new contract
		const randomWallet = await Utils.getRandomColdWallet(context);

		const balanceBefore = await EvmCalls.getErc20BalanceOf(context, erc20Address, randomWallet.address);
		assert.equal(balanceBefore, 0n);

		const transferTx = await EvmCalls.makeEvmCall(context, {
			recipient: erc20Address,
			payload: EvmCalls.encodeErc20Transfer(randomWallet.address, ethers.parseEther("1234")),
		});

		({ accept } = await addTransactionsToPool(context, [transferTx]));
		assert.equal(accept, [0]);

		await waitBlock(context);
		await isTransactionCommitted(context, transferTx);

		// Check final balance
		const balanceAfter = await EvmCalls.getErc20BalanceOf(context, erc20Address, randomWallet.address);
		assert.equal(balanceAfter, ethers.parseEther("1234"));
	});
});
