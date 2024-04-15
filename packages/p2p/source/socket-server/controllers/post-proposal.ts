import Hapi from "@hapi/hapi";
import { inject, injectable } from "@mainsail/container";
import { Contracts, Identifiers } from "@mainsail/contracts";
import { performance } from "perf_hooks";

import { getPeerIp } from "../../utils/index.js";

@injectable()
export class PostProposalController implements Contracts.P2P.Controller {
	@inject(Identifiers.Consensus.Processor.Proposal)
	private readonly proposalProcessor!: Contracts.Consensus.ProposalProcessor;

	@inject(Identifiers.Cryptography.Message.Factory)
	private readonly factory!: Contracts.Crypto.MessageFactory;

	@inject(Identifiers.P2P.Peer.Disposer)
	private readonly peerDisposer!: Contracts.P2P.PeerDisposer;

	@inject(Identifiers.P2P.State)
	private readonly state!: Contracts.P2P.State;

	@inject(Identifiers.Services.Log.Service)
	private readonly logger!: Contracts.Kernel.Logger;

	public async handle(
		request: Contracts.P2P.PostProposalRequest,
		h: Hapi.ResponseToolkit,
	): Promise<Contracts.P2P.PostProposalResponse> {
		try {
			this.logger.info(`!!!Received proposal ${request.payload.proposal.length} bytes`);

			const t1 = performance.now();

			const proposal = await this.factory.makeProposalFromBytes(request.payload.proposal);

			const t2 = performance.now();

			const result = await this.proposalProcessor.process(proposal);

			const t3 = performance.now();

			this.logger.info(`!!!Processing proposal ${proposal.block.block.data.id} took ${t2 - t1}ms, ${t3 - t2}ms`);

			if (result === Contracts.Consensus.ProcessorResult.Invalid) {
				throw new Error("Invalid proposal");
			}

			this.state.resetLastMessageTime();
		} catch (error) {
			this.peerDisposer.banPeer(getPeerIp(request), error.message);
		}

		return {};
	}
}
