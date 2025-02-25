import { inject, injectable, optional } from "@mainsail/container";
import { Contracts, Exceptions, Identifiers } from "@mainsail/contracts";
import { TransactionConstructor } from "@mainsail/crypto-transaction";
import { Utils as AppUtils } from "@mainsail/kernel";
import { Handlers } from "@mainsail/transactions";

import { UsernameRegistrationTransaction } from "../versions/index.js";

@injectable()
export class UsernameRegistrationTransactionHandler extends Handlers.TransactionHandler {
	@inject(Identifiers.TransactionPool.Query)
	@optional()
	private readonly poolQuery?: Contracts.TransactionPool.Query;

	public dependencies(): ReadonlyArray<Handlers.TransactionHandlerConstructor> {
		return [];
	}

	public getConstructor(): TransactionConstructor {
		return UsernameRegistrationTransaction;
	}

	public async isActivated(): Promise<boolean> {
		return true;
	}

	public async throwIfCannotBeApplied(
		context: Contracts.Transactions.TransactionHandlerContext,
		transaction: Contracts.Crypto.Transaction,
		wallet: Contracts.State.Wallet,
	): Promise<void> {
		const { data }: Contracts.Crypto.Transaction = transaction;

		AppUtils.assert.defined<Contracts.Crypto.TransactionAsset>(data.asset);
		AppUtils.assert.defined<string>(data.asset.username);

		if (context.walletRepository.hasByIndex(Contracts.State.WalletIndexes.Usernames, data.asset.username)) {
			throw new Exceptions.WalletUsernameAlreadyRegisteredError(data.asset.username);
		}

		return super.throwIfCannotBeApplied(context, transaction, wallet);
	}

	public async throwIfCannotEnterPool(
		context: Contracts.Transactions.TransactionHandlerContext,
		transaction: Contracts.Crypto.Transaction,
	): Promise<void> {
		AppUtils.assert.defined<Contracts.TransactionPool.Query>(this.poolQuery);

		const { data }: Contracts.Crypto.Transaction = transaction;

		AppUtils.assert.defined<string>(data.senderPublicKey);
		AppUtils.assert.defined<Contracts.Crypto.TransactionAsset>(data.asset);
		AppUtils.assert.defined<string>(data.asset.username);

		const hasSender: boolean = await this.poolQuery
			.getAllBySender(data.senderPublicKey)
			.whereKind(transaction)
			.has();

		if (hasSender) {
			throw new Exceptions.PoolError(
				`Sender ${data.senderPublicKey} already has a transaction of type '${Contracts.Crypto.TransactionType.UsernameRegistration}' in the pool`,
				"ERR_PENDING",
			);
		}

		const username = data.asset.username;
		const hasUsername: boolean = await this.poolQuery
			.getAll()
			.whereKind(transaction)
			.wherePredicate(async (t) => t.data.asset?.username === username)
			.has();

		if (hasUsername) {
			throw new Exceptions.PoolError(
				`Username registration for username "${username}" already in the pool`,
				"ERR_PENDING",
			);
		}
	}

	public async applyToSender(
		context: Contracts.Transactions.TransactionHandlerContext,
		transaction: Contracts.Crypto.Transaction,
	): Promise<Contracts.Transactions.TransactionApplyResult> {
		const { data }: Contracts.Crypto.Transaction = transaction;

		AppUtils.assert.defined<Contracts.Crypto.TransactionAsset>(data.asset);
		AppUtils.assert.defined<string>(data.asset.username);

		const result = await super.applyToSender(context, transaction);

		const sender: Contracts.State.Wallet = await context.walletRepository.findByPublicKey(data.senderPublicKey);

		if (sender.hasAttribute("username")) {
			context.walletRepository.forgetOnIndex(
				Contracts.State.WalletIndexes.Usernames,
				sender.getAttribute("username"),
			);
		}

		sender.setAttribute("username", data.asset.username);
		context.walletRepository.setOnIndex(Contracts.State.WalletIndexes.Usernames, data.asset.username, sender);

		return result;
	}

	public async applyToRecipient(
		context: Contracts.Transactions.TransactionHandlerContext,
		transaction: Contracts.Crypto.Transaction,
	): Promise<Contracts.Transactions.TransactionApplyResult> {
		return super.applyToRecipient(context, transaction);
	}
}
