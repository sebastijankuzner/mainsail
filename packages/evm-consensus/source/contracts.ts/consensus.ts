export const abi = {
	abi: [
		{ inputs: [], stateMutability: "nonpayable", type: "constructor" },
		{
			inputs: [],
			name: "activeValidatorsCount",
			outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
			stateMutability: "view",
			type: "function",
		},
		{
			inputs: [{ internalType: "uint8", name: "n", type: "uint8" }],
			name: "calculateTopValidators",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{ inputs: [], name: "deregisterValidator", outputs: [], stateMutability: "nonpayable", type: "function" },
		{
			inputs: [{ internalType: "uint8", name: "n", type: "uint8" }],
			name: "getActiveValidators",
			outputs: [
				{
					components: [
						{ internalType: "address", name: "addr", type: "address" },
						{
							components: [
								{ internalType: "uint256", name: "voteBalance", type: "uint256" },
								{ internalType: "bool", name: "isResigning", type: "bool" },
								{ internalType: "bytes", name: "bls12_381_public_key", type: "bytes" },
							],
							internalType: "struct ValidatorData",
							name: "data",
							type: "tuple",
						},
					],
					internalType: "struct Validator[]",
					name: "",
					type: "tuple[]",
				},
			],
			stateMutability: "view",
			type: "function",
		},
		{
			inputs: [],
			name: "getTopValidators",
			outputs: [
				{
					components: [
						{ internalType: "address", name: "addr", type: "address" },
						{
							components: [
								{ internalType: "uint256", name: "voteBalance", type: "uint256" },
								{ internalType: "bool", name: "isResigning", type: "bool" },
								{ internalType: "bytes", name: "bls12_381_public_key", type: "bytes" },
							],
							internalType: "struct ValidatorData",
							name: "data",
							type: "tuple",
						},
					],
					internalType: "struct Validator[]",
					name: "",
					type: "tuple[]",
				},
			],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			inputs: [{ internalType: "address", name: "_addr", type: "address" }],
			name: "getValidator",
			outputs: [
				{
					components: [
						{ internalType: "address", name: "addr", type: "address" },
						{
							components: [
								{ internalType: "uint256", name: "voteBalance", type: "uint256" },
								{ internalType: "bool", name: "isResigning", type: "bool" },
								{ internalType: "bytes", name: "bls12_381_public_key", type: "bytes" },
							],
							internalType: "struct ValidatorData",
							name: "data",
							type: "tuple",
						},
					],
					internalType: "struct Validator",
					name: "",
					type: "tuple",
				},
			],
			stateMutability: "view",
			type: "function",
		},
		{
			inputs: [{ internalType: "address", name: "addr", type: "address" }],
			name: "isValidatorRegistered",
			outputs: [{ internalType: "bool", name: "", type: "bool" }],
			stateMutability: "view",
			type: "function",
		},
		{
			inputs: [],
			name: "performValidatorResignations",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			inputs: [{ internalType: "bytes", name: "bls12_381_public_key", type: "bytes" }],
			name: "registerValidator",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			inputs: [],
			name: "registeredValidatorsCount",
			outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
			stateMutability: "view",
			type: "function",
		},
		{ inputs: [], name: "shuffle", outputs: [], stateMutability: "nonpayable", type: "function" },
		{ inputs: [], name: "updateActiveValidators", outputs: [], stateMutability: "nonpayable", type: "function" },
		{
			inputs: [],
			name: "updateActiveValidatorsMerge",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			inputs: [
				{
					components: [
						{ internalType: "address", name: "addr", type: "address" },
						{
							components: [
								{ internalType: "uint256", name: "voteBalance", type: "uint256" },
								{ internalType: "bool", name: "isResigning", type: "bool" },
								{ internalType: "bytes", name: "bls12_381_public_key", type: "bytes" },
							],
							internalType: "struct ValidatorData",
							name: "data",
							type: "tuple",
						},
					],
					internalType: "struct Validator",
					name: "_validator",
					type: "tuple",
				},
			],
			name: "updateValidator",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			inputs: [{ internalType: "address[]", name: "voters", type: "address[]" }],
			name: "updateVoters",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			inputs: [{ internalType: "address", name: "addr", type: "address" }],
			name: "vote",
			outputs: [],
			stateMutability: "nonpayable",
			type: "function",
		},
		{
			anonymous: false,
			inputs: [
				{ indexed: false, internalType: "address", name: "voter", type: "address" },
				{ indexed: false, internalType: "address", name: "validator", type: "address" },
			],
			name: "Voted",
			type: "event",
		},
	],
	bytecode:
		"0x60a0604052600080556001600855348015601857600080fd5b50336080526080516127e46100386000396000610b0101526127e46000f3fe608060405234801561001057600080fd5b50600436106101005760003560e01c80636a911ccf11610097578063afeea11511610066578063afeea115146101ca578063b5cfa68c146101d2578063d04a68c7146101e5578063f1bd0b371461022157600080fd5b80636a911ccf1461019c5780636dd7d8ea146101a45780637c1f669a146101b75780638bc3dd9b1461014657600080fd5b80632520bf04116100d35780632520bf041461014e5780632bdf6d431461015657806348948ede14610169578063602a9eee1461018957600080fd5b80630d2bd909146101055780630f062c641461011c5780631904bb2e1461012657806321eb1a9514610146575b600080fd5b6009545b6040519081526020015b60405180910390f35b610124610229565b005b610139610134366004612144565b610612565b60405161011391906121f1565b610124610769565b610124610789565b610124610164366004612204565b6108e8565b61017c610177366004612279565b61092f565b604051610113919061229c565b610124610197366004612301565b610af7565b610124610d83565b6101246101b2366004612144565b610e90565b6101246101c5366004612363565b611004565b61017c6110a1565b6101246101e0366004612279565b611239565b6102116101f3366004612144565b6001600160a01b031660009081526003602052604090205460ff1690565b6040519015158152602001610113565b600054610109565b600a546000906001600160401b038111156102465761024661239d565b60405190808252806020026020018201604052801561026f578160200160208202803683370190505b50905060005b600a5481101561043d576000600a8281548110610294576102946123b3565b60009182526020808320909101546001600160a01b03168083526001918290526040909220908101549192509060ff166103155760405162461bcd60e51b815260206004820152601a60248201527f56616c696461746f72206973206e6f742072657369676e696e6700000000000060448201526064015b60405180910390fd5b60008160020160405161032891906123fd565b604051908190039020600080549192508061034283612488565b90915550506001600160a01b0383166000908152600360209081526040808320805460ff199081169091556001928390529083208381559182018054909116905590610391600283018261202c565b50506000818152600260205260408120805460ff191690555b6005546103b99060019061249f565b85101561042d57836001600160a01b0316600582815481106103dd576103dd6123b3565b6000918252602090912001546001600160a01b03160361041b578086868151811061040a5761040a6123b3565b60200260200101818152505061042d565b80610425816124b2565b9150506103aa565b5050600190920191506102759050565b5060005b815181101561051d5760006104578260016124cb565b90505b825181101561051457828181518110610475576104756123b3565b602002602001015183838151811061048f5761048f6123b3565b6020026020010151101561050c578281815181106104af576104af6123b3565b60200260200101518383815181106104c9576104c96123b3565b60200260200101518484815181106104e3576104e36123b3565b602002602001018584815181106104fc576104fc6123b3565b6020908102919091010191909152525b60010161045a565b50600101610441565b5060005b815181101561060257600082828151811061053e5761053e6123b3565b602002602001015190506005600160058054905061055c919061249f565b8154811061056c5761056c6123b3565b600091825260209091200154600580546001600160a01b039092169183908110610598576105986123b3565b9060005260206000200160006101000a8154816001600160a01b0302191690836001600160a01b0316021790555060058054806105d7576105d76124de565b600082815260209020810160001990810180546001600160a01b031916905501905550600101610521565b5061060f600a6000612066565b50565b61061a612084565b6001600160a01b03821660009081526003602052604090205460ff166106825760405162461bcd60e51b815260206004820152601c60248201527f56616c696461746f724461746120646f65736e27742065786973747300000000604482015260640161030c565b6040805180820182526001600160a01b038416808252600090815260016020818152918490208451606081018652815481529181015460ff1615158284015260028101805494959386019492939192918401916106de906123c9565b80601f016020809104026020016040519081016040528092919081815260200182805461070a906123c9565b80156107575780601f1061072c57610100808354040283529160200191610757565b820191906000526020600020905b81548152906001019060200180831161073a57829003601f168201915b50505091909252505050905292915050565b610787600560006001600580549050610782919061249f565b61158b565b565b600554600061079960018361249f565b90505b80156108e45760006107af8260016124cb565b604080514260208201524491810191909152606081018490526080016040516020818303038152906040528051906020012060001c6107ee919061250a565b9050600060058381548110610805576108056123b3565b600091825260209091200154600580546001600160a01b0390921692509083908110610833576108336123b3565b600091825260209091200154600580546001600160a01b03909216918590811061085f5761085f6123b3565b9060005260206000200160006101000a8154816001600160a01b0302191690836001600160a01b0316021790555080600583815481106108a1576108a16123b3565b9060005260206000200160006101000a8154816001600160a01b0302191690836001600160a01b03160217905550505080806108dc90612488565b91505061079c565b5050565b60005b8181101561092a57610922838383818110610908576109086123b3565b905060200201602081019061091d9190612144565b6115e3565b6001016108eb565b505050565b606060006109478360ff1660006005805490506116c0565b905060008160ff166001600160401b038111156109665761096661239d565b60405190808252806020026020018201604052801561099f57816020015b61098c612084565b8152602001906001900390816109845790505b50905060005b8260ff16811015610aef576000600582815481106109c5576109c56123b3565b6000918252602090912001546001600160a01b03169050806109e657600080fd5b6001600160a01b038116600081815260016020818152604092839020835180850185529485528351606081018552815481529281015460ff16151583830152600281018054919594928501939286929084019190610a43906123c9565b80601f0160208091040260200160405190810160405280929190818152602001828054610a6f906123c9565b8015610abc5780601f10610a9157610100808354040283529160200191610abc565b820191906000526020600020905b815481529060010190602001808311610a9f57829003601f168201915b505050505081525050815250848481518110610ada57610ada6123b3565b602090810291909101015250506001016109a5565b509392505050565b6001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000163303610b605760405162461bcd60e51b815260206004820152600e60248201526d24b73b30b634b21031b0b63632b960911b604482015260640161030c565b3360009081526003602052604090205460ff1615610bcc5760405162461bcd60e51b815260206004820152602360248201527f56616c696461746f724461746120697320616c726561647920726567697374656044820152621c995960ea1b606482015260840161030c565b60008282604051610bde92919061251e565b604080519182900390912060008181526002602052919091205490915060ff1615610c575760405162461bcd60e51b815260206004820152602360248201527f424c5331322d333831206b657920697320616c726561647920726567697374656044820152621c995960ea1b606482015260840161030c565b610c618383611752565b600060405180606001604052806000815260200160001515815260200185858080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201829052509390945250508054929350905080610cc7836124b2565b90915550503360009081526003602090815260408083208054600160ff199182168117909255818452938290208551815592850151908301805490941690151517909255908201518291906002820190610d21908261257c565b505050600091825250600260205260408120805460ff191660019081179091556005805491820181559091527f036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db00180546001600160a01b031916331790555050565b3360009081526003602052604090205460ff16610ddb5760405162461bcd60e51b815260206004820152601660248201527521b0b63632b9103737ba1030903b30b634b230ba37b960511b604482015260640161030c565b3360009081526001602081905260409091209081015460ff1615610e415760405162461bcd60e51b815260206004820152601e60248201527f56616c696461746f7220697320616c72656164792072657369676e696e670000604482015260640161030c565b6001908101805460ff191682179055600a805491820181556000527fc65a7bb8d6351c1cf70c95a316cc6a92839c986682d98bc35f958f4883f9d2a80180546001600160a01b03191633179055565b6001600160a01b03811660009081526003602052604090205460ff16610ef85760405162461bcd60e51b815260206004820152601760248201527f6d75737420766f746520666f722076616c696461746f72000000000000000000604482015260640161030c565b336000908152600460205260409020546001600160a01b031615610f545760405162461bcd60e51b81526020600482015260136024820152721513d113ce88185b1c9958591e481d9bdd1959606a1b604482015260640161030c565b6040805180820182526001600160a01b038381168083523380316020808601918252600083815260048252878120965187546001600160a01b0319169616959095178655905160019586015591835292905291822080549131929091610fbb9084906124cb565b9091555050604080513381526001600160a01b03831660208201527fce0c7a2a940807f7dc2ce7a615c2532e915e6c0ac9a08bc4ed9d515a710a53e2910160405180910390a150565b6110146101f36020830183612144565b6110605760405162461bcd60e51b815260206004820152601c60248201527f56616c696461746f724461746120646f65736e27742065786973747300000000604482015260640161030c565b61106d602082018261263a565b6001600061107e6020850185612144565b6001600160a01b03168152602081019190915260400160002061092a8282612719565b6009546060906000906001600160401b038111156110c1576110c161239d565b6040519080825280602002602001820160405280156110fa57816020015b6110e7612084565b8152602001906001900390816110df5790505b50905060005b6009548110156112335760006009828154811061111f5761111f6123b3565b60009182526020808320909101546001600160a01b03168083526001808352604093849020845180860186528381528551606081018752825481529282015460ff161515838601526002820180549497509195909485019386929184019190611187906123c9565b80601f01602080910402602001604051908101604052809291908181526020018280546111b3906123c9565b80156112005780601f106111d557610100808354040283529160200191611200565b820191906000526020600020905b8154815290600101906020018083116111e357829003601f168201915b50505050508152505081525084848151811061121e5761121e6123b3565b60209081029190910101525050600101611100565b50919050565b600560008154811061124d5761124d6123b3565b600091825260209091200154600680546001600160a01b0319166001600160a01b039092169190911790558060015b6005548110156114b85760006005828154811061129b5761129b6123b3565b6000918252602090912001546008546001600160a01b03909116915060ff841611156112d0576112ca816117b0565b506114b0565b6001600160a01b038082166000818152600160208181526040808420600654909616845292839020835180850185529485528351606081018552865481529286015460ff16151583830152600286018054919561149e95909493850193928892918401919061133e906123c9565b80601f016020809104026020016040519081016040528092919081815260200182805461136a906123c9565b80156113b75780601f1061138c576101008083540402835291602001916113b7565b820191906000526020600020905b81548152906001019060200180831161139a57829003601f168201915b5050509190925250505090526040805180820182526006546001600160a01b03168152815160608101835285548152600186015460ff161515602082810191909152600287018054939491850193889284019190611414906123c9565b80601f0160208091040260200160405190810160405280929190818152602001828054611440906123c9565b801561148d5780601f106114625761010080835404028352916020019161148d565b820191906000526020600020905b81548152906001019060200180831161147057829003601f168201915b505050505081525050815250611aec565b156114ac576114ac836117b0565b5050505b60010161127c565b506006546001600160a01b031660ff82166001600160401b038111156114e0576114e061239d565b604051908082528060200260200182016040528015611509578160200160208202803683370190505b50805161151e916009916020909101906120ca565b5060005b8260ff16811015611585578160098281548110611541576115416123b3565b600091825260208083209190910180546001600160a01b0319166001600160a01b039485161790559382168152600790935260409092205490911690600101611522565b50505050565b8082101561092a57600060026115a1848461249f565b6115ab919061279a565b6115b590846124cb565b90506115c284848361158b565b6115d7846115d18360016124cb565b8461158b565b61158584848385611b2e565b6001600160a01b0380821660009081526004602052604090208054909116611609575050565b60018101546001600160a01b0383163181101561166857611634816001600160a01b0385163161249f565b82546001600160a01b03166000908152600160205260408120805490919061165d9084906124cb565b909155506116ab9050565b61167c6001600160a01b038416318261249f565b82546001600160a01b0316600090815260016020526040812080549091906116a590849061249f565b90915550505b506001600160a01b0390911631600190910155565b60008183111561172a5760405162461bcd60e51b815260206004820152602f60248201527f4d696e696d756d2073686f756c64206265206c657373207468616e206f72206560448201526e7175616c20746f206d6178696d756d60881b606482015260840161030c565b8284101561173957508161174b565b8184111561174857508061174b565b50825b9392505050565b603081146108e45760405162461bcd60e51b815260206004820152602560248201527f424c5331322d333831207075626c69634b6579206c656e67746820697320696e6044820152641d985b1a5960da1b606482015260840161030c565b6006546040805180820182526001600160a01b03848116808352600090815260016020818152918590208551606081018752815481529181015460ff1615158284015260028101805494909716966118f896938601949293919291840191611817906123c9565b80601f0160208091040260200160405190810160405280929190818152602001828054611843906123c9565b80156118905780601f1061186557610100808354040283529160200191611890565b820191906000526020600020905b81548152906001019060200180831161187357829003601f168201915b5050509190925250505090526040805180820182526001600160a01b038516808252600090815260016020818152918490208451606081018652815481529181015460ff161515828401526002810180549495938601949293919291840191611414906123c9565b61190a5761190582611f7b565b611a96565b805b6001600160a01b038216611929576119248184611fcd565b611a94565b6040805180820182526001600160a01b038516808252600090815260016020818152918490208451606081018652815481529181015460ff16151582840152600281018054611a64969486019484019190611983906123c9565b80601f01602080910402602001604051908101604052809291908181526020018280546119af906123c9565b80156119fc5780601f106119d1576101008083540402835291602001916119fc565b820191906000526020600020905b8154815290600101906020018083116119df57829003601f168201915b5050509190925250505090526040805180820182526001600160a01b038616808252600090815260016020818152918490208451606081018652815481529181015460ff161515828401526002810180549495938601949293919291840191611414906123c9565b611a72576119248184611fcd565b506001600160a01b03808216600090815260076020526040902054169061190c565b505b603560085411156108e457600680546001600160a01b038082166000908152600760205260408120549091166001600160a01b03199092168217909255600880549192611ae283612488565b9190505550505050565b6020808201515190830151516000919003611b195750805182516001600160a01b03918216911611611b28565b50602080820151519083015151115b92915050565b6000611b3a848461249f565b611b459060016124cb565b90506000611b53848461249f565b90506000826001600160401b03811115611b6f57611b6f61239d565b604051908082528060200260200182016040528015611b98578160200160208202803683370190505b5090506000826001600160401b03811115611bb557611bb561239d565b604051908082528060200260200182016040528015611bde578160200160208202803683370190505b50905060005b84811015611c575788611bf7828a6124cb565b81548110611c0757611c076123b3565b9060005260206000200160009054906101000a90046001600160a01b0316838281518110611c3757611c376123b3565b6001600160a01b0390921660209283029190910190910152600101611be4565b5060005b83811015611cda578881611c708960016124cb565b611c7a91906124cb565b81548110611c8a57611c8a6123b3565b9060005260206000200160009054906101000a90046001600160a01b0316828281518110611cba57611cba6123b3565b6001600160a01b0390921660209283029190910190910152600101611c5b565b50600080885b8683108015611cee57508582105b15611e74576000858481518110611d0757611d076123b3565b602002602001015190506000858481518110611d2557611d256123b3565b6020908102919091018101516040805180820182526001600160a01b03861680825260009081526001808652908390208351606081018552815481529181015460ff16151582870152600281018054959750611d919693959386019492939192840191611817906123c9565b15611dfd57868581518110611da857611da86123b3565b60200260200101518d8481548110611dc257611dc26123b3565b600091825260209091200180546001600160a01b0319166001600160a01b039290921691909117905584611df5816124b2565b955050611e60565b858481518110611e0f57611e0f6123b3565b60200260200101518d8481548110611e2957611e296123b3565b600091825260209091200180546001600160a01b0319166001600160a01b039290921691909117905583611e5c816124b2565b9450505b82611e6a816124b2565b9350505050611ce0565b86831015611ef157848381518110611e8e57611e8e6123b3565b60200260200101518b8281548110611ea857611ea86123b3565b600091825260209091200180546001600160a01b0319166001600160a01b039290921691909117905582611edb816124b2565b9350508080611ee9906124b2565b915050611e74565b85821015611f6e57838281518110611f0b57611f0b6123b3565b60200260200101518b8281548110611f2557611f256123b3565b600091825260209091200180546001600160a01b0319166001600160a01b039290921691909117905581611f58816124b2565b9250508080611f66906124b2565b915050611ef1565b5050505050505050505050565b600680546001600160a01b0383811660008181526007602052604081208054939094166001600160a01b0319938416179093558354909116179091556008805491611fc5836124b2565b919050555050565b6001600160a01b0382811660008181526007602052604080822080548686168085529284208054919096166001600160a01b031991821617909555928252825490931690921790556008805491612023836124b2565b91905055505050565b508054612038906123c9565b6000825580601f10612048575050565b601f01602090049060005260206000209081019061060f919061212f565b508054600082559060005260206000209081019061060f919061212f565b604051806040016040528060006001600160a01b031681526020016120c5604051806060016040528060008152602001600015158152602001606081525090565b905290565b82805482825590600052602060002090810192821561211f579160200282015b8281111561211f57825182546001600160a01b0319166001600160a01b039091161782556020909201916001909101906120ea565b5061212b92915061212f565b5090565b5b8082111561212b5760008155600101612130565b60006020828403121561215657600080fd5b81356001600160a01b038116811461174b57600080fd5b60018060a01b038151168252600060208201516040602085015280516040850152602081015115156060850152604081015190506060608085015280518060a086015260005b818110156121d057602081840181015160c08884010152016121b3565b50600060c0828701015260c0601f19601f8301168601019250505092915050565b60208152600061174b602083018461216d565b6000806020838503121561221757600080fd5b82356001600160401b0381111561222d57600080fd5b8301601f8101851361223e57600080fd5b80356001600160401b0381111561225457600080fd5b8560208260051b840101111561226957600080fd5b6020919091019590945092505050565b60006020828403121561228b57600080fd5b813560ff8116811461174b57600080fd5b6000602082016020835280845180835260408501915060408160051b86010192506020860160005b828110156122f557603f198786030184526122e085835161216d565b945060209384019391909101906001016122c4565b50929695505050505050565b6000806020838503121561231457600080fd5b82356001600160401b0381111561232a57600080fd5b8301601f8101851361233b57600080fd5b80356001600160401b0381111561235157600080fd5b85602082840101111561226957600080fd5b60006020828403121561237557600080fd5b81356001600160401b0381111561238b57600080fd5b82016040818503121561174b57600080fd5b634e487b7160e01b600052604160045260246000fd5b634e487b7160e01b600052603260045260246000fd5b600181811c908216806123dd57607f821691505b60208210810361123357634e487b7160e01b600052602260045260246000fd5b600080835461240b816123c9565b600182168015612422576001811461243757612467565b60ff1983168652811515820286019350612467565b86600052602060002060005b8381101561245f57815488820152600190910190602001612443565b505081860193505b509195945050505050565b634e487b7160e01b600052601160045260246000fd5b60008161249757612497612472565b506000190190565b81810381811115611b2857611b28612472565b6000600182016124c4576124c4612472565b5060010190565b80820180821115611b2857611b28612472565b634e487b7160e01b600052603160045260246000fd5b634e487b7160e01b600052601260045260246000fd5b600082612519576125196124f4565b500690565b8183823760009101908152919050565b601f82111561092a57806000526020600020601f840160051c810160208510156125555750805b601f840160051c820191505b818110156125755760008155600101612561565b5050505050565b81516001600160401b038111156125955761259561239d565b6125a9816125a384546123c9565b8461252e565b6020601f8211600181146125dd57600083156125c55750848201515b600019600385901b1c1916600184901b178455612575565b600084815260208120601f198516915b8281101561260d57878501518255602094850194600190920191016125ed565b508482101561262b5786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b60008235605e1983360301811261265057600080fd5b9190910192915050565b6001600160401b038311156126715761267161239d565b6126858361267f83546123c9565b8361252e565b6000601f8411600181146126b957600085156126a15750838201355b600019600387901b1c1916600186901b178355612575565b600083815260209020601f19861690835b828110156126ea57868501358255602094850194600190920191016126ca565b50868210156127075760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b8135815560018101602083013580151580821461273557600080fd5b60ff19835416915060ff8116821783555050506040820135601e1983360301811261275f57600080fd5b820180356001600160401b0381111561277757600080fd5b60208201915080360382131561278c57600080fd5b61158581836002860161265a565b6000826127a9576127a96124f4565b50049056fea2646970667358221220ab3925520b2d45103daeabad38bdc72df7c22886e8884935abca160c3c8aa78764736f6c634300081a0033",
};
