import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const EvidenceChainModule = buildModule("EvidenceChainModule", (m) => {
  const evidenceChain = m.contract("EvidenceChain");
  return { evidenceChain };
});

export default EvidenceChainModule;