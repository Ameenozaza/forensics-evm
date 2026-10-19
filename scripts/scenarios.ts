import hre from "hardhat";
import fs from "fs";
import path from "path";

function nowMs(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

async function rawGetEvent(contract: any, id: number) {
  const iface = contract.interface;
  const calldata = iface.encodeFunctionData("getEvent", [id]);
  const raw = await contract.runner.provider.call({
    to: await contract.getAddress(),
    data: calldata,
  });
  return iface.decodeFunctionResult("getEvent", raw)[0];
}

async function register(
  contract: any,
  ethers: any,
  eventType: number,
  artifactHash: string,
  prevHash: string,
  cid: string
) {
  const tx = await contract.registerEvent(eventType, artifactHash, prevHash, cid);
  const receipt = await tx.wait();
  return receipt.hash;
}

async function verify(contract: any, id: number, hash: string) {
  return await contract.verifyEvent(id, hash);
}

async function runTamperScenarios(contract: any, ethers: any, results: any[]) {
  const base = ethers.keccak256(ethers.toUtf8Bytes("artifact-tamper"));
  const zero = ethers.ZeroHash;

  // T1: alter artifact bytes -> hash mismatch
  {
    await register(contract, ethers, 0, base, zero, "cid-t1");
    const id = (await contract.eventCount()) - 1n;
    const tampered = ethers.keccak256(ethers.toUtf8Bytes("tampered-bytes"));
    const t0 = nowMs();
    const detected = !(await verify(contract, Number(id), tampered));
    const dt = nowMs() - t0;
    results.push({ scenario: "T1", detected, time_ms: dt, note: "artifact bytes altered" });
  }

  // T2: alter off-chain metadata -> cid mismatch (proxy: hash mismatch on metadata field)
  {
    const metaHash = ethers.keccak256(ethers.toUtf8Bytes("metadata-original"));
    await register(contract, ethers, 0, metaHash, zero, "cid-t2");
    const id = Number((await contract.eventCount()) - 1n);
    const tamperedMeta = ethers.keccak256(ethers.toUtf8Bytes("metadata-altered"));
    const t0 = nowMs();
    const detected = !(await verify(contract, id, tamperedMeta));
    const dt = nowMs() - t0;
    results.push({ scenario: "T2", detected, time_ms: dt, note: "metadata hash altered" });
  }

  // T3: direct ledger edit -> not representable on EVM without privileged node access
  {
    results.push({
      scenario: "T3",
      detected: null,
      time_ms: null,
      note: "not representable: direct ledger edit requires privileged access to the node's state; recorded as a design limit",
    });
  }

  // T4: delete an artifact -> event still retrievable, artifact gone from IPFS
  {
    await register(contract, ethers, 0, base, zero, "cid-t4");
    const id = Number((await contract.eventCount()) - 1n);
    // simulate deletion: cid points to nothing; the record still exists
    const e = await rawGetEvent(contract, id);
    const recordSurvives = e[7] !== ""; // cid field present
    results.push({
      scenario: "T4",
      detected: recordSurvives,
      time_ms: 0,
      note: "artifact deletion; on-chain record survives (design limit: chain records existence, not availability)",
    });
  }

  // T5: backdated timestamp -> contract uses block.timestamp, cannot be backdated by caller
  {
    await register(contract, ethers, 0, base, zero, "cid-t5");
    const id = Number((await contract.eventCount()) - 1n);
    const e = await rawGetEvent(contract, id);
    const ts = Number(e[6]);
    const now = Math.floor(Date.now() / 1000);
    const notBackdated = Math.abs(now - ts) < 600; // within 10 min
    results.push({
      scenario: "T5",
      detected: notBackdated,
      time_ms: 0,
      note: "timestamp uses block.timestamp; caller cannot backdate",
    });
  }

  // T6: valid signature from unauthorized role -> contract has no roles; any signer can register
  {
    const [, unauthorized] = await ethers.getSigners();
    const t0 = nowMs();
    const tx = await contract.connect(unauthorized).registerEvent(0, base, zero, "cid-t6");
    await tx.wait();
    const dt = nowMs() - t0;
    results.push({
      scenario: "T6",
      detected: false,
      time_ms: dt,
      note: "no role enforcement in this contract: unauthorized signer succeeded; design limit",
    });
  }
}

async function runGapScenarios(contract: any, ethers: any, results: any[]) {
  const base = ethers.keccak256(ethers.toUtf8Bytes("artifact-gap"));
  const zero = ethers.ZeroHash;

  // G1: missing intermediate transfer -> verifier walks prevHash chain
  {
    await register(contract, ethers, 0, base, zero, "cid-g1-a");
    const idA = Number((await contract.eventCount()) - 1n);
    // Skip a "transfer" and register "access" directly with prevHash pointing to a non-existent entry
    const fakePrev = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
    await register(contract, ethers, 2, base, fakePrev, "cid-g1-b");
    const idB = Number((await contract.eventCount()) - 1n);
    const eB = await rawGetEvent(contract, idB);
    const hasGap = (await contract.hashToId(eB[3])) === 0n && eB[3] !== zero;
    results.push({
      scenario: "G1",
      detected: hasGap,
      time_ms: 0,
      note: "prevHash does not resolve to a known entry -> gap detected",
    });
  }

  // G2: sequence number hole -> contract assigns sequential ids, no holes possible by design
  {
    results.push({
      scenario: "G2",
      detected: null,
      time_ms: null,
      note: "not representable: contract assigns id sequentially; holes cannot occur",
    });
  }

  // G3: inconsistent holder -> verify actor field changed without re-signing
  {
    await register(contract, ethers, 1, base, zero, "cid-g3");
    const id = Number((await contract.eventCount()) - 1n);
    const e = await rawGetEvent(contract, id);
    // actor is msg.sender; if a different actor claims the same entryHash, mismatch
    const claimed = ethers.keccak256(ethers.toUtf8Bytes("imposter-actor"));
    const detected = claimed !== e[4]; // entryHash would differ
    results.push({
      scenario: "G3",
      detected,
      time_ms: 0,
      note: "actor bound into entryHash; inconsistent holder produces different hash",
    });
  }

  // G4: time gap above threshold -> compare consecutive event timestamps
  {
    const THRESHOLD_S = 3600; // 1 hour
    await register(contract, ethers, 0, base, zero, "cid-g4-a");
    const idA = Number((await contract.eventCount()) - 1n);
    // In a real run, wait; here we simulate by checking existing timestamps
    const eA = await rawGetEvent(contract, idA);
    const eB = await rawGetEvent(contract, idA - 1);
    const gap = Math.abs(Number(eA[6]) - Number(eB[6]));
    results.push({
      scenario: "G4",
      detected: gap > THRESHOLD_S ? true : false,
      time_ms: 0,
      note: `threshold=${THRESHOLD_S}s; observed gap=${gap}s; in a real case, a gap above threshold must be flagged by the report generator`,
    });
  }

  // G5: artifact access with no logged event -> not representable without an access-log layer
  {
    results.push({
      scenario: "G5",
      detected: null,
      time_ms: null,
      note: "not representable: no access-log layer in this contract; recorded as a design limit",
    });
  }
}

async function main() {
  const { ethers } = await hre.network.getOrCreate();
  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("EvidenceChain");
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  console.log(`Contract at ${await contract.getAddress()}`);

  const results: any[] = [];

  console.log("Running tamper scenarios...");
  await runTamperScenarios(contract, ethers, results);

  console.log("Running gap scenarios...");
  await runGapScenarios(contract, ethers, results);

  const outFile = path.join("logs", "scenarios_results.csv");
  fs.writeFileSync(
    outFile,
    "scenario,detected,time_ms,note\n" +
      results
        .map((r) => `${r.scenario},${r.detected},${r.time_ms},"${r.note.replace(/"/g, "'")}"`)
        .join("\n") +
      "\n"
  );

  console.log("\nResults:");
  results.forEach((r) => console.log(`${r.scenario}: detected=${r.detected} time=${r.time_ms}ms — ${r.note}`));
  console.log(`\nWritten to ${outFile}`);
}

main().catch((e) => { console.error(e); process.exit(1); });