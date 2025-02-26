import { Column, Entity, Unique } from "typeorm";

@Entity({
	name: "blocks",
})
@Unique("unique_block_height", ["height"])
@Unique("unique_block_timestamp", ["timestamp"])
@Unique("unique_previous_block", ["previousBlock"])
export class Block {
	@Column({
		primary: true,
		type: "varchar",
	})
	public readonly id!: string;

	@Column({
		type: "smallint",
	})
	public readonly version!: number;

	@Column({
		nullable: false,
		type: "bigint",
	})
	public readonly timestamp!: string;

	@Column({
		type: "varchar",
	})
	public readonly previousBlock!: string;

	@Column({
		type: "varchar",
	})
	public readonly stateHash!: string;

	@Column({
		nullable: false,
		type: "bigint",
	})
	public readonly height!: string;

	@Column({
		nullable: false,
		type: "integer",
	})
	public readonly numberOfTransactions!: number;

	@Column({
		nullable: false,
		type: "integer",
	})
	public readonly totalGasUsed!: number;

	@Column({
		nullable: false,
		type: "numeric",
	})
	public readonly totalAmount!: string;

	@Column({
		nullable: false,
		type: "numeric",
	})
	public readonly totalFee!: string;

	@Column({
		nullable: false,
		type: "numeric",
	})
	public readonly reward!: string;

	@Column({
		nullable: false,
		type: "integer",
	})
	public readonly payloadLength!: number;

	@Column({
		nullable: false,
		type: "varchar",
	})
	public readonly payloadHash!: string;

	@Column({
		nullable: false,
		type: "varchar",
	})
	public readonly generatorPublicKey!: string;

	@Column({
		nullable: false,
		type: "integer",
	})
	public readonly round!: number;

	@Column({
		nullable: false,
		type: "integer",
	})
	public readonly commitRound!: number;

	@Column({
		nullable: false,
		type: "integer",
	})
	public readonly validatorRound!: number;

	@Column({
		nullable: false,
		type: "bigint",
	})
	public readonly validatorSet!: string;

	@Column({
		nullable: false,
		type: "varchar",
	})
	public readonly signature!: string;
}
