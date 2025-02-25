import { Contracts } from "@mainsail/contracts";
import { BigNumber } from "@mainsail/utils";

import { Wallet, WalletRepository } from "../source/wallets";

export const buildValidatorAndVoteWallets = async (
	addressFactory: Contracts.Crypto.AddressFactory,
	numberDelegates: number,
	walletRepo: WalletRepository,
): Promise<Wallet[]> => {
	const delegates: Wallet[] = [];
	const delegateKeys: string[] = [
		"02511f16ffb7b7e9afc12f04f317a11d9644e4be9eb5a5f64673946ad0f6336f34",
		"0259d9ca7922c277b0e7407a88703bbb98f5da43a335b0eefa6c4642f072acfe79",
		"03697abb61ee85e020a35a1d2701112e7e16477ac9d2eb2e8900a27995edc917a2",
		"027e2269d8a770343223bedc49bab31b3c52fb4c1df6627153e6374ac23e2d878b",
		"03858d4d3b77c7c227f6fe3e18b5807aa476828cb712663dcd79df87e439cc07c5",
	];

	const voterKeys: string[] = [
		"03858d4d3b77c7c227f6fe3e18b5807aa476828cb712663dcd79df87e439cc07c6",
		"03858d4d3b77c7c227f6fe3e18b5807aa476828cb712663dcd79df87e439cc07c7",
		"03858d4d3b77c7c227f6fe3e18b5807aa476828cb712663dcd79df87e439cc0710",
		"03858d4d3b77c7c227f6fe3e18b5807aa476828cb712663dcd79df87e439cc6f34",
		"03858d4d3b77c7c227f6fe3e18b5807aa476828cb712663dcd79df87e439cc6f35",
	];

	if (numberDelegates > delegateKeys.length) {
		throw new Error(`Number of Test Delegates (${numberDelegates}) should not exceed ${delegateKeys.length}`);
	}

	for (let index = 0; index < numberDelegates; index++) {
		const delegateKey = delegateKeys[index];
		const delegate = await walletRepo.findByPublicKey(await addressFactory.fromPublicKey(delegateKey));
		delegate.setAttribute("validatorVoteBalance", BigNumber.ZERO);

		// @ts-ignore
		delegate.events = undefined;

		const voter = await walletRepo.findByPublicKey(voterKeys[index]);
		const totalBalance = BigNumber.make(index + 1)
			.times(1000)
			.times(BigNumber.WEI);
		voter.setBalance(totalBalance);
		voter.setPublicKey(`v${delegateKey}`);
		voter.setAttribute("vote", delegateKey);

		// @ts-ignore
		voter.events = undefined;

		walletRepo.index([delegate, voter]);
		delegates.push(delegate as Wallet);
	}
	return delegates;
};
