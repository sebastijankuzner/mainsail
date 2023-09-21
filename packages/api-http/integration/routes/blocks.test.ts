import { describe, Sandbox } from "../../../test-framework";
import { prepareSandbox, ApiContext } from "../../test/helpers/prepare-sandbox";
import { request } from "../../test/helpers/request";

import blocks from "../../test/fixtures/blocks.json";

describe<{
	sandbox: Sandbox;
}>("Blocks", ({ it, afterAll, assert, afterEach, beforeAll, beforeEach, nock }) => {
	let apiContext: ApiContext;

	// TODO:
	let options = { transform: false };

	beforeAll(async (context) => {
		nock.enableNetConnect();
		apiContext = await prepareSandbox(context);
	});

	afterAll((context) => {
		nock.disableNetConnect();
		apiContext.dispose();
	});

	beforeEach(async (context) => {
		await apiContext.reset();
	});

	afterEach(async (context) => {
		await apiContext.reset();
	});

	it("/blocks", async () => {
		const { statusCode, data } = await request("/blocks", options);
		assert.equal(statusCode, 200);
	});

	it("/blocks/first", async () => {
		await apiContext.blockRepository.save(blocks);

		const { statusCode, data } = await request("/blocks/first", options);
		assert.equal(statusCode, 200);
		assert.equal(data.data, blocks[blocks.length - 1]);
	});

	it("/blocks/{height}", async () => {
		await apiContext.blockRepository.save(blocks);

		const { statusCode, data } = await request("/blocks/1", options);
		assert.equal(statusCode, 200);
		assert.equal(data.data, blocks[blocks.length - 1]);
	});

	it("/blocks/{id}", async () => {
		await apiContext.blockRepository.save(blocks);

		const id = blocks[blocks.length - 1].id;
		const { statusCode, data } = await request(`/blocks/${id}`, options);
		assert.equal(statusCode, 200);
		assert.equal(data.data, blocks[blocks.length - 1]);
	});

	it("/blocks/{id}/transactions", async () => {
		const { statusCode, data } = await request("/blocks/1/transactions", options);
		assert.equal(statusCode, 200);
	});
});
