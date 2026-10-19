import { expect } from "chai";
import hre from "hardhat";

describe("EvidenceChain", function () {
  async function deploy() {
    const { ethers } = await hre.network.getOrCreate();
    const [deployer] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("EvidenceChain");
    const contract = await factory.deploy();
    await contract.waitForDeployment();
    return { contract, deployer, ethers };
  }

  // Use raw eth_call to avoid Hardhat 3 proxy issues with struct returns
  async function rawGetEvent(contract: any, id: number, ethers: any) {
    const iface = contract.interface;
    const calldata = iface.encodeFunctionData("getEvent", [id]);
    const raw = await contract.runner.provider.call({
      to: await contract.getAddress(),
      data: calldata,
    });
    const decoded = iface.decodeFunctionResult("getEvent", raw);
    // decoded[0] is the struct, returned as a Result array
    return decoded[0];
  }

  it("registers a first event and reads it back", async function () {
    const { contract, ethers } = await deploy();
    const artifactHash = ethers.keccak256(ethers.toUtf8Bytes("evidence-001"));
    const zero = ethers.ZeroHash;

    const tx = await contract.registerEvent(0, artifactHash, zero, "QmCIDexample");
    await tx.wait();

    const e = await rawGetEvent(contract, 0, ethers);
    // Struct fields are ordered: id, eventType, artifactHash, prevHash, entryHash, actor, timestamp, cid
    expect(e[2]).to.equal(artifactHash); // artifactHash is the 3rd field (index 2)
    expect(e[3]).to.equal(zero);        // prevHash is the 4th field (index 3)
    expect(await contract.eventCount()).to.equal(1n);
  });

  it("links a second event to the first via prevHash", async function () {
    const { contract, ethers } = await deploy();
    const artifactHash = ethers.keccak256(ethers.toUtf8Bytes("evidence-001"));

    await (await contract.registerEvent(0, artifactHash, ethers.ZeroHash, "cid-1")).wait();
    const first = await rawGetEvent(contract, 0, ethers);

    await (await contract.registerEvent(1, artifactHash, first[4], "cid-2")).wait(); // first[4] is entryHash
    const second = await rawGetEvent(contract, 1, ethers);
    expect(second[3]).to.equal(first[4]); // second.prevHash == first.entryHash
  });

  it("verifies a correct entryHash and rejects a wrong one", async function () {
    const { contract, ethers } = await deploy();
    const artifactHash = ethers.keccak256(ethers.toUtf8Bytes("evidence-001"));
    await (await contract.registerEvent(0, artifactHash, ethers.ZeroHash, "cid-1")).wait();

    const e = await rawGetEvent(contract, 0, ethers);
    const entryHash = e[4]; // entryHash is the 5th field (index 4)

    // verifyEvent takes (uint256, bytes32) and returns bool — this doesn't return a struct, so direct call is fine
    expect(await contract.verifyEvent(0, entryHash)).to.equal(true);

    const wrong = ethers.keccak256(ethers.toUtf8Bytes("wrong"));
    expect(await contract.verifyEvent(0, wrong)).to.equal(false);
  });
});