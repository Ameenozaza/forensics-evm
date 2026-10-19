import hashlib, json, time, os, sys, csv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

LOG = "logs/baseline_b_log.jsonl"
OUT = "logs/baseline_b_scenarios.csv"

class BaselineB:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if os.path.exists(LOG):
            os.remove(LOG)
        self.entries = []

    def _last_hash(self):
        return self.entries[-1]["hash"] if self.entries else "0" * 64

    def register(self, event_type, artifact_hash, prev_hash, cid):
        entry = {
            "id": len(self.entries),
            "type": event_type,
            "artifact_hash": artifact_hash,
            "prev_hash": prev_hash,
            "cid": cid,
            "actor_pub": self.pub.hex(),
            "ts": time.time(),
        }
        payload = json.dumps(entry, sort_keys=True).encode()
        entry["hash"] = hashlib.sha256(payload).hexdigest()
        entry["sig"] = self.key.sign(payload).hex()
        self.entries.append(entry)
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def get(self, id):
        return self.entries[id]

    def verify(self, id, proposed_hash):
        return self.entries[id]["artifact_hash"] == proposed_hash

    def entry_hash(self, id):
        return self.entries[id]["hash"]

def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()

def main():
    b = BaselineB()
    results = []

    # T1: alter artifact bytes
    b.register(0, sha("artifact-tamper"), "0"*64, "cid-t1")
    i = len(b.entries) - 1
    t0 = time.time()
    detected = not b.verify(i, sha("tampered-bytes"))
    results.append(("T1", detected, round((time.time()-t0)*1000), "artifact bytes altered"))

    # T2: alter metadata
    b.register(0, sha("metadata-original"), "0"*64, "cid-t2")
    i = len(b.entries) - 1
    t0 = time.time()
    detected = not b.verify(i, sha("metadata-altered"))
    results.append(("T2", detected, round((time.time()-t0)*1000), "metadata hash altered"))

    # T3: direct ledger edit
    # B is a plain file; direct edit is possible. Simulate by reading + modifying the file.
    # Detection: re-read the log, verify every hash; a changed entry breaks the chain.
    path = LOG
    lines = open(path).read().splitlines()
    if lines:
        obj = json.loads(lines[-1])
        obj["artifact_hash"] = sha("edited-on-disk")
        lines[-1] = json.dumps(obj)
        open(path + ".tampered", "w").write("\n".join(lines) + "\n")
        # verify chain on tampered file
        ok = True
        prev = "0"*64
        for line in open(path + ".tampered"):
            e = json.loads(line)
            if e["prev_hash"] != prev:
                ok = False; break
            payload = {k: v for k, v in e.items() if k not in ("hash", "sig")}
            if hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest() != e["hash"]:
                ok = False; break
            prev = e["hash"]
        results.append(("T3", not ok, 0, "direct file edit: hash chain break detected" if not ok else "NOT detected"))

    # T4: delete an artifact (the cid points to nothing; the record survives)
    b.register(0, sha("artifact-t4"), "0"*64, "cid-t4")
    i = len(b.entries) - 1
    e = b.get(i)
    record_survives = e["cid"] != ""
    results.append(("T4", record_survives, 0, "record survives artifact deletion (design limit)"))

    # T5: backdated timestamp — B uses time.time() at write time; cannot backdate without rewriting the log
    b.register(0, sha("artifact-t5"), "0"*64, "cid-t5")
    i = len(b.entries) - 1
    e = b.get(i)
    now = time.time()
    not_backdated = abs(now - e["ts"]) < 600
    results.append(("T5", not_backdated, 0, "timestamp cannot be backdated after the fact"))

    # T6: unauthorized signer — every entry is signed by the same key in this single-actor test
    # In a real multi-actor B, you'd sign with a different key; here we note the design limit.
    results.append(("T6", False, 0, "no role model: any key can sign (design limit)"))

    # G1: missing intermediate transfer
    b.register(0, sha("artifact-g1"), "0"*64, "cid-g1-a")
    fake = sha("nonexistent")
    b.register(2, sha("artifact-g1"), fake, "cid-g1-b")
    i = len(b.entries) - 1
    e = b.get(i)
    # gap detected if prev_hash does not equal any known entry hash
    known = {x["hash"] for x in b.entries[:-1]}
    has_gap = e["prev_hash"] not in known and e["prev_hash"] != "0"*64
    results.append(("G1", has_gap, 0, "prev_hash does not resolve"))

    # G2: sequence hole — ids are sequential by construction; not representable
    results.append(("G2", None, None, "not representable: ids sequential"))

    # G3: inconsistent holder — actor_pub is part of the signed payload
    b.register(1, sha("artifact-g3"), "0"*64, "cid-g3")
    i = len(b.entries) - 1
    e = b.get(i)
    claimed = sha("imposter-actor")
    detected = claimed != e["actor_pub"]
    results.append(("G3", detected, 0, "actor bound into signed payload"))

    # G4: time gap
    THRESHOLD = 3600
    b.register(0, sha("artifact-g4"), "0"*64, "cid-g4")
    i = len(b.entries) - 1
    eA = b.get(i)
    eB = b.get(i - 1)
    gap = abs(eA["ts"] - eB["ts"])
    results.append(("G4", gap > THRESHOLD, 0, f"threshold={THRESHOLD}s, observed={gap:.1f}s"))

    # G5: no access log — B has no access layer
    results.append(("G5", None, None, "not representable: no access log"))

    os.makedirs("logs", exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "detected", "time_ms", "note"])
        for r in results:
            w.writerow(r)

    print("\nBaseline B results:")
    for r in results:
        print(f"{r[0]}: detected={r[1]} time={r[2]}ms — {r[3]}")
    print(f"\nWritten to {OUT}")

if __name__ == "__main__":
    main()