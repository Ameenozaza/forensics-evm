// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EvidenceChain
/// @notice On-chain anchor for digital evidence chain-of-custody.
/// Off-chain artifact bytes are stored in IPFS; only hashes go on-chain.
contract EvidenceChain {
    enum EventType { Register, Transfer, Access, Derive, Verify, Seal }

    struct Event {
        uint256 id;
        EventType eventType;
        bytes32 artifactHash;
        bytes32 prevHash;
        bytes32 entryHash;
        address actor;
        uint64 timestamp;
        string cid;
    }

    uint256 public eventCount;
    mapping(uint256 => Event) public events;
    mapping(bytes32 => uint256) public hashToId;

    event EventRegistered(
        uint256 indexed id,
        EventType eventType,
        bytes32 artifactHash,
        bytes32 entryHash,
        address indexed actor,
        uint64 timestamp
    );

    /// @notice Append a new custody event. prevHash must equal the entryHash
    /// of the previous event for this artifact, or bytes32(0) for the first.
    function registerEvent(
        EventType eventType,
        bytes32 artifactHash,
        bytes32 prevHash,
        string calldata cid
    ) external returns (uint256 id) {
        id = eventCount;

        bytes32 entryHash = keccak256(
            abi.encodePacked(
                id,
                eventType,
                artifactHash,
                prevHash,
                msg.sender,
                uint64(block.timestamp),
                cid
            )
        );

        events[id] = Event({
            id: id,
            eventType: eventType,
            artifactHash: artifactHash,
            prevHash: prevHash,
            entryHash: entryHash,
            actor: msg.sender,
            timestamp: uint64(block.timestamp),
            cid: cid
        });

        hashToId[entryHash] = id;
        eventCount += 1;

        emit EventRegistered(id, eventType, artifactHash, entryHash, msg.sender, uint64(block.timestamp));
    }

    /// @notice Read a single event by id.
    function getEvent(uint256 id) external view returns (Event memory) {
        require(id < eventCount, "no such event");
        return events[id];
    }

    /// @notice Verify that a proposed entryHash matches the stored one for id.
    function verifyEvent(uint256 id, bytes32 proposedHash) external view returns (bool) {
        require(id < eventCount, "no such event");
        return events[id].entryHash == proposedHash;
    }
}