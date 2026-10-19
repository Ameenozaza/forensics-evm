import hre from "hardhat";
import fs from "fs";
import path from "path";

const EVENT_TYPES = ["register", "transfer", "access", "derive", "verify", "seal"] as const;
const EVENT_TYPE_ENUM: Record<string, number> = {
  register: 0, transfer: 1, access: 2, derive: 3, verify: 4, seal: 5,
};

function nowMs(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

function pseudoArtifactHash(ethers: any, caseId: number, seq: number): string {
  return ethers.keccak256(ethers.toUtf8Bytes(`artifact-${caseId}-${seq}`));
}

async function runCase(
  contract: any,
  ethers: any,
  caseId: number,
  concurrency: number,
  eventsPerCase: number,
  outFile: string
) {
  const totalEvents = eventsPerCase;
  const perWorker = Math.ceil(totalEvents / concurrency);
  const latencies: number[] = [];
  let failures = 0;

  const runWorker = async (workerId: number) => {
    let prevHash = ethers.ZeroHash;
    for (let i = 0; i < perWorker; i++) {
      const seq = workerId * perWorker + i;
      if (seq >= totalEvents) break;

      const eventType = EVENT_TYPE_ENUM[EVENT_TYPES[seq % EVENT_TYPES.length]];
      const artifactHash = pseudoArtifactHash(ethers, caseId, seq);

      const t0 = nowMs();
      try {
        const tx = await contract.registerEvent(eventType, artifactHash, prevHash, `cid-${seq}`);
        const receipt = await tx.wait();
        const t1 = nowMs();
        latencies.push(t1 - t0);
        // For chain-linking: next event in this worker links to this tx hash
        prevHash = receipt.hash;
      } catch (err) {
        failures++;
      }
    }
  };

  const tStart = nowMs();
  await Promise.all(Array.from({ length: concurrency }, (_, w) => runWorker(w)));
  const tEnd = nowMs();

  const durationMs = tEnd - tStart;
  const warmupCount = Math.floor(totalEvents * 0.1);
  const measured = latencies.slice(warmupCount);
  const tps = (measured.length / durationMs) * 1000;

  measured.sort((a, b) => a - b);
  const p = (q: number) => measured.length ? measured[Math.floor(measured.length * q)] : 0;

  const row = {
    case_id: caseId,
    concurrency,
    events: totalEvents,
    duration_ms: durationMs,
    tps: tps.toFixed(2),
    p50_ms: p(0.5),
    p95_ms: p(0.95),
    p99_ms: p(0.99),
    failures,
  };

  console.log(
    `case=${caseId} conc=${concurrency} events=${totalEvents} ` +
    `tps=${row.tps} p50=${row.p50_ms} p95=${row.p95_ms} p99=${row.p99_ms} fail=${failures}`
  );

  const header = Object.keys(row).join(",") + "\n";
  const line = Object.values(row).join(",") + "\n";
  if (!fs.existsSync(outFile)) fs.writeFileSync(outFile, header);
  fs.appendFileSync(outFile, line);
}

async function main() {
  const { ethers } = await hre.network.getOrCreate();
  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("EvidenceChain");
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  console.log(`EvidenceChain deployed at ${await contract.getAddress()}`);

  const outFile = path.join("logs", "grid_results.csv");
  if (fs.existsSync(outFile)) fs.unlinkSync(outFile);

  const caseSizes = [1000];
  const concurrencies = [1, 10, 100];

  let caseId = 0;
  for (const caseSize of caseSizes) {
    for (const conc of concurrencies) {
      caseId++;
      await runCase(contract, ethers, caseId, conc, caseSize, outFile);
    }
  }

  console.log(`\nResults written to ${outFile}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});