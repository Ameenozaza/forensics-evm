import hre from "hardhat";
import fs from "fs";
import path from "path";

async function rawGetEvent(contract: any, id: number) {
  const iface = contract.interface;
  const calldata = iface.encodeFunctionData("getEvent", [id]);
  const raw = await contract.runner.provider.call({
    to: await contract.getAddress(), data: calldata,
  });
  return iface.decodeFunctionResult("getEvent", raw)[0];
}

async function main() {
  const { ethers } = await hre.network.getOrCreate();
  const [deployer] = await ethers.getSigners();
  const factory = await ethers.getContractFactory("EvidenceChain");
  const contract = await factory.deploy();
  await contract.waitForDeployment();

  const N = 20;
  let correct = 0, falsePositives = 0;
  for (let i = 0; i < N; i++) {
    const hash = ethers.keccak256(ethers.toUtf8Bytes(`untouched-${i}`));
    await (await contract.registerEvent(0, hash, ethers.ZeroHash, `cid-${i}`)).wait();
    const e = await rawGetEvent(contract, i);
    const ok = await contract.verifyEvent(i, e[4]);
    if (ok) correct++;
    else falsePositives++;
  }
  console.log(`Untouched cases: ${N}, correct verifications: ${correct}, false positives: ${falsePositives}`);
  const out = path.join("logs", "falsepositives.csv");
  fs.writeFileSync(out, `n,correct,false_positives\n${N},${correct},${falsePositives}\n`);
  console.log(`Written to ${out}`);
}
main().catch((e) => { console.error(e); process.exit(1); });