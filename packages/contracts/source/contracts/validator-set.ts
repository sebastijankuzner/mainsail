import { CommitHandler } from "./crypto";
import { ValidatorWallet } from "./state";

export interface Service extends CommitHandler {
	initialize(): Promise<void>;
	getActiveValidators(): ValidatorWallet[];
	getValidator(validatorIndex: number): ValidatorWallet;
	getValidatorIndexByWalletPublicKey(walletPublicKey: string): number;
}
