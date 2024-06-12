import { Contracts } from "@mainsail/contracts";
import { BigNumberish, ethers, randomBytes } from "ethers";

import { describe, Sandbox } from "../../../test-framework/distribution";
import * as MainsailERC20 from "../../test/fixtures/MainsailERC20.json";
import * as MainsailGlobals from "../../test/fixtures/MainsailGlobals.json";
import { wallets } from "../../test/fixtures/wallets";
import { prepareSandbox } from "../../test/helpers/prepare-sandbox";
import { EvmInstance } from "./evm";
import { setGracefulCleanup } from "tmp";

describe<{
	sandbox: Sandbox;
	instance: Contracts.Evm.Instance;
}>("Instance", ({ it, assert, afterAll, beforeEach }) => {
	afterAll(() => setGracefulCleanup());

	beforeEach(async (context) => {
		await prepareSandbox(context);

		context.instance = context.sandbox.app.resolve<Contracts.Evm.Instance>(EvmInstance);
	});

	const deployGasConfig = {
		gasLimit: BigInt(1_000_000),
	};

	const gasConfig = {
		gasLimit: BigInt(60_000),
	};

	const blockContext: Omit<Contracts.Evm.BlockContext, "commitKey"> = {
		gasLimit: BigInt(10_000_000),
		timestamp: BigInt(12345),
		validatorAddress: ethers.ZeroAddress,
	};

	it("should deploy contract successfully", async ({ instance }) => {
		const [sender] = wallets;

		const commitKey = { height: BigInt(0), round: BigInt(0) };
		const { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey },
			txHash: getRandomTxHash(),
			...deployGasConfig,
		});

		assert.true(receipt.success);
		assert.equal(receipt.gasUsed, 964_156n);
		assert.equal(receipt.deployedContractAddress, "0x0c2485e7d05894BC4f4413c52B080b6D1eca122a");
	});

	// Also see
	// https://docs.soliditylang.org/en/latest/units-and-global-variables.html#block-and-transaction-properties
	it("should correctly set global variables", async ({ instance }) => {
		const [validator, sender] = wallets;

		const iface = new ethers.Interface(MainsailGlobals.abi);

		const commitKey = { height: BigInt(0), round: BigInt(0) };
		let { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailGlobals.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey },
			txHash: getRandomTxHash(),
			...deployGasConfig,
		});

		assert.true(receipt.success);
		assert.equal(receipt.deployedContractAddress, "0x69230f08D82f095aCB9BE4B21043B502b712D3C1");
		await instance.onCommit({ height: BigInt(0), round: BigInt(0) } as any);

		const encodedCall = iface.encodeFunctionData("emitGlobals");
		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(ethers.getBytes(encodedCall)),
			recipient: "0x69230f08D82f095aCB9BE4B21043B502b712D3C1",
			txHash: getRandomTxHash(),
			blockContext: {
				commitKey: { height: BigInt(1245), round: BigInt(0) },
				gasLimit: BigInt(12_000_000),
				timestamp: BigInt(123_456_789),
				validatorAddress: validator.address,
			},
			...gasConfig,
		}));

		const data = iface.decodeEventLog("GlobalData", receipt.logs[0].data)[0];

		// struct Globals {
		//     uint256 blockHeight;
		//     uint256 blockTimestamp;
		//     uint256 blockGasLimit;
		//     address blockCoinbase;
		//     uint256 blockDifficulty;
		//     uint256 txGasPrice;
		//     address txOrigin;
		// }
		assert.equal(data[0], 1245n);
		assert.equal(data[1], 123_456_789n);
		assert.equal(data[2], 12_000_000n);
		assert.equal(data[3], validator.address);
		assert.equal(data[4], 0n); // difficulty always 0
		assert.equal(data[5], 0n); // gas price always 0
		assert.equal(data[6], sender.address);
	});

	it("should deploy, transfer and and update balance correctly", async ({ instance }) => {
		const [sender, recipient] = wallets;

		let { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			txHash: getRandomTxHash(),
			blockContext: { ...blockContext, commitKey: { height: BigInt(0), round: BigInt(0) } },
			...deployGasConfig,
		});

		await instance.onCommit({ height: BigInt(0), round: BigInt(0) } as any);

		assert.true(receipt.success);
		assert.equal(receipt.gasUsed, 964_156n);
		assert.equal(receipt.deployedContractAddress, "0x0c2485e7d05894BC4f4413c52B080b6D1eca122a");

		const contractAddress = receipt.deployedContractAddress;
		assert.defined(contractAddress);

		const iface = new ethers.Interface(MainsailERC20.abi);

		const balanceBefore = await getBalance(instance, contractAddress!, sender.address);
		assert.equal(ethers.parseEther("100000000"), balanceBefore);

		const amount = ethers.parseEther("1999");

		const transferEncodedCall = iface.encodeFunctionData("transfer", [recipient.address, amount]);
		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(ethers.getBytes(transferEncodedCall)),
			recipient: contractAddress,
			txHash: getRandomTxHash(),
			blockContext: { ...blockContext, commitKey: { height: BigInt(1), round: BigInt(0) } },
			...gasConfig,
		}));

		await instance.onCommit({ height: BigInt(1), round: BigInt(0) } as any);

		assert.true(receipt.success);
		assert.equal(receipt.gasUsed, 52_222n);

		const balanceAfter = await getBalance(instance, contractAddress!, recipient.address);
		assert.equal(amount, balanceAfter);
	});

	it("should revert on invalid call", async ({ instance }) => {
		const [sender] = wallets;

		let { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			txHash: getRandomTxHash(),
			blockContext: { ...blockContext, commitKey: { height: BigInt(0), round: BigInt(0) } },
			...deployGasConfig,
		});

		const contractAddress = receipt.deployedContractAddress;
		assert.defined(contractAddress);

		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from("0xdead", "hex"),
			recipient: contractAddress,
			txHash: getRandomTxHash(),
			blockContext: { ...blockContext, commitKey: { height: BigInt(0), round: BigInt(0) } },
			...gasConfig,
		}));

		assert.false(receipt.success);
		assert.equal(receipt.gasUsed, 21_070n);
	});

	it("should overwrite pending state if modified in different context", async ({ instance }) => {
		const [sender, recipient] = wallets;

		const commitKey = { height: BigInt(0), round: BigInt(0) };

		let { receipt } = await instance.process({
			blockContext: { ...blockContext, commitKey },
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			txHash: getRandomTxHash(),
			...deployGasConfig,
		});

		const contractAddress = receipt.deployedContractAddress;
		assert.defined(contractAddress);

		await instance.onCommit(commitKey as any);

		//

		const iface = new ethers.Interface(MainsailERC20.abi);

		const commitKey1 = { height: BigInt(1), round: BigInt(0) };
		const commitKey2 = { height: BigInt(1), round: BigInt(1) };

		// Transfer 1 ARK (1,0)
		await assert.resolves(
			async () =>
				await instance.process({
					blockContext: { ...blockContext, commitKey: commitKey1 },
					caller: sender.address,
					data: Buffer.from(
						ethers.getBytes(
							iface.encodeFunctionData("transfer", [recipient.address, ethers.parseEther("1")]),
						),
					),
					recipient: contractAddress,
					txHash: getRandomTxHash(),
					...gasConfig,
				}),
		);

		// Transfer 2 ARK (1,1)
		await assert.resolves(async () => {
			await instance.process({
				blockContext: { ...blockContext, commitKey: commitKey2 },
				caller: sender.address,
				data: Buffer.from(
					ethers.getBytes(iface.encodeFunctionData("transfer", [recipient.address, ethers.parseEther("2")])),
				),
				recipient: contractAddress,
				txHash: getRandomTxHash(),
				...gasConfig,
			});
		});

		// Commit (1,0) fails since it was overwritten
		await assert.rejects(async () => instance.onCommit(commitKey1 as any), "invalid commit key");
		// Commit (1,1) succeeds
		await assert.resolves(async () => instance.onCommit(commitKey2 as any));

		// Balance updated correctly
		const balance = await getBalance(instance, contractAddress!, recipient.address);
		assert.equal(ethers.parseEther("2"), balance);
	});

	it("should not throw when commit is empty", async ({ instance }) => {
		await assert.resolves(async () => await instance.onCommit({ height: 0, round: 0 } as any));
	});

	it("should throw on invalid tx context caller", async ({ instance }) => {
		await assert.rejects(
			async () =>
				await instance.process({
					caller: "badsender_",
					data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
					blockContext: { ...blockContext, commitKey: { height: BigInt(0), round: BigInt(0) } },
					txHash: getRandomTxHash(),
					...deployGasConfig,
				}),
		);
	});

	it("should return existing receipt when already committed", async ({ instance }) => {
		const [sender] = wallets;

		const commitKey = { height: BigInt(0), round: BigInt(0) };
		const txHash = getRandomTxHash();
		let { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey },
			txHash,
			...deployGasConfig,
		});

		assert.true(receipt.success);
		assert.equal(receipt.gasUsed, 964_156n);
		assert.equal(receipt.deployedContractAddress, "0x0c2485e7d05894BC4f4413c52B080b6D1eca122a");
		assert.length(receipt.logs, 1);

		await instance.onCommit(commitKey as any);

		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey },
			txHash,
			...deployGasConfig,
		}));

		assert.true(receipt.success);
		assert.equal(receipt.gasUsed, 964_156n);
		assert.equal(receipt.deployedContractAddress, "0x0c2485e7d05894BC4f4413c52B080b6D1eca122a");
		assert.null(receipt.logs);
	});

	it("should throw when passing non-existent tx hash for committed receipt", async ({ instance }) => {
		const [sender] = wallets;

		const commitKey = { height: BigInt(0), round: BigInt(0) };
		const txHash = getRandomTxHash();

		await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey },
			txHash,
			...deployGasConfig,
		});

		await instance.onCommit(commitKey as any);

		const randomTxHash = getRandomTxHash();

		await assert.rejects(async () => {
			await instance.process({
				caller: sender.address,
				data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
				blockContext: { ...blockContext, commitKey },
				txHash: randomTxHash,
				...deployGasConfig,
			});
		}, "found commit, but tx hash is missing");
	});

	it("should deploy, transfer multipe times and update balance correctly", async ({ instance }) => {
		const [sender, recipient] = wallets;

		let { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey: { height: BigInt(0), round: BigInt(0) } },
			txHash: getRandomTxHash(),
			...deployGasConfig,
		});

		await instance.onCommit({ height: BigInt(0), round: BigInt(0) } as any);

		assert.true(receipt.success);
		assert.equal(receipt.gasUsed, 964_156n);
		assert.equal(receipt.deployedContractAddress, "0x0c2485e7d05894BC4f4413c52B080b6D1eca122a");

		const contractAddress = receipt.deployedContractAddress;
		assert.defined(contractAddress);

		const iface = new ethers.Interface(MainsailERC20.abi);
		const amount = ethers.parseEther("1999");

		const transferEncodedCall = iface.encodeFunctionData("transfer", [recipient.address, amount]);
		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(ethers.getBytes(transferEncodedCall)),
			recipient: contractAddress,
			blockContext: { ...blockContext, commitKey: { height: BigInt(1), round: BigInt(0) } },
			txHash: getRandomTxHash(),
			...gasConfig,
		}));

		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(ethers.getBytes(transferEncodedCall)),
			recipient: contractAddress,
			blockContext: { ...blockContext, commitKey: { height: BigInt(1), round: BigInt(0) } },
			txHash: getRandomTxHash(),
			...gasConfig,
		}));

		({ receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(ethers.getBytes(transferEncodedCall)),
			recipient: contractAddress,
			blockContext: { ...blockContext, commitKey: { height: BigInt(1), round: BigInt(0) } },
			txHash: getRandomTxHash(),
			...gasConfig,
		}));

		// not updated yet
		const balanceBefore = await getBalance(instance, contractAddress!, recipient.address);
		assert.equal(ethers.parseEther("0"), balanceBefore);

		await instance.onCommit({ height: BigInt(1), round: BigInt(0) } as any);

		// Balance updated correctly
		const balanceAfteer = await getBalance(instance, contractAddress!, recipient.address);
		assert.equal(ethers.parseEther("5997"), balanceAfteer);
	});

	it("should revert transaction if it exceeds gas limit", async ({ instance }) => {
		const [sender] = wallets;

		const commitKey = { height: BigInt(0), round: BigInt(0) };
		const { receipt } = await instance.process({
			caller: sender.address,
			data: Buffer.from(MainsailERC20.bytecode.slice(2), "hex"),
			blockContext: { ...blockContext, commitKey },
			txHash: getRandomTxHash(),
			gasLimit: 30_000n,
		});

		assert.false(receipt.success);
		assert.equal(receipt.gasUsed, 30_000n);
	});
});

const getRandomTxHash = () => Buffer.from(randomBytes(32)).toString("hex");

const getBalance = async (
	instance: Contracts.Evm.Instance,
	contractAddress: string,
	walletAddress: string,
): Promise<BigNumberish> => {
	const iface = new ethers.Interface(MainsailERC20.abi);
	const balanceOf = iface.encodeFunctionData("balanceOf", [walletAddress]);

	const { output } = await instance.view({
		caller: ethers.ZeroAddress,
		data: Buffer.from(ethers.getBytes(balanceOf)),
		recipient: contractAddress!,
	});

	const [balance] = iface.decodeFunctionResult("balanceOf", output!);
	return balance;
};
