import hre from "hardhat";
import fs from "fs";
import path from "path";

function nowMs(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

async function buildCase(contract: any, ethers: any, caseId: number, k: number) {
  let prevHash = ethers.ZeroHash;
  for (let i = 0; i < k; i++) {
    const artifactHash = ethers.keccak256(ethers.toUtf8Bytes(`artifact-${caseId}-${i}`));
    const tx = await contract.registerEvent(i % 6, artifactHash, prevHash, `cid-${caseId}-${i}`);
    const receipt = await tx.wait();
    prevHash = receipt.hash;
  }
}

async function measureReport(contract: any, k: number) {
  const iface = contract.interface;
  const t0 = nowMs();
  let bytesRead = 0;
  for (let id = 0; id < k; id++) {
    const calldata = iface.encodeFunctionData("getEvent", [id]);
    const raw = await contract.runner.provider.call({
      to: await contract.getAddress(),
      data: calldata,
    });
    bytesRead += raw.length / 2 - 1; // hex chars -> bytes
  }
  const t1 = nowMs();
  return { timeMs: t1 - t0, bytesRead };
}

async function main() {
  const { ethers } = await hre.network.getOrCreate();
  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("EvidenceChain");
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  console.log(`Contract at ${await contract.getAddress()}`);

  const outFile = path.join("logs", "audit_results.csv");
  if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
  fs.writeFileSync(outFile, "k,time_ms,bytes_read\n");

  const ks = [100, 1000, 10000];
  let caseId = 0;
  for (const k of ks) {
    caseId++;
    console.log(`Building case with k=${k} events...`);
    await buildCase(contract, ethers, caseId, k);
    const r = await measureReport(contract, k);
    console.log(`k=${k}: report time=${r.timeMs}ms, bytes=${r.bytesRead}`);
    fs.appendFileSync(outFile, `${k},${r.timeMs},${r.bytesRead}\n`);
  }
  console.log(`\nResults written to ${outFile}`);
}

main().catch((e) => { console.error(e); process.exit(1); });