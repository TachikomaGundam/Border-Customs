# Provenance — fixtures-local (W2.4b G-LOCAL local-lane live proofs)

Created 2026-09-11 by the W2.4b FIX ROUND working session (HEAD 1208dc5, uncommitted tree),
after VERIFIER-REPORT-W24B-SHADOW.json disproved the previous DONECLAIM's planted-wheel live
proof. These are the canonical, durable bytes every future local-lane proof sha must reference
(the disproven round's ephemeral `6620b266…` / `9236b41d…` shas are retired — their fixtures
were never persisted). Reproducible from `src/` (same commands: `npm pack` in each package dir,
`python3 src/wheel*/build.py` — note the builders write into `../dist` beside their own dir;
copy the artifact out). Integrity: `sha256sum -c SUMS`.

## rt-plant-npm-1.0.0.tgz — sha256 70435f93c270d93c087c34a3c32fdf666101cbf691b32d17c56d8f2b58d540cb
Honest replacement plant for the local lane, npm ecosystem: postinstall (executed by
`npm install -g --foreground-scripts`; ran even under npm 11.19.0's install-scripts WARNING)
appends `export RT_W24B_PLANT_MARKER=1` to /etc/profile and writes executable
/usr/local/bin/rt-plant-orphan — both OUTSIDE npm's tracked trees. Expected verdict: FAIL /
exit 1 with EXACTLY 2 rows (HIGH roundtrip-residue-file /usr/local/bin/rt-plant-orphan,
CRITICAL roundtrip-modified-persistence /etc/profile), equal 1:1 to the manual docker ground
truth in manual-ground-truth-node24.21.0-npm11.19.0.txt. Cited by: this fix round's DONECLAIM
(npm_live_plant) and NPM-LIVE-PROOF-2026-09-11.md; resolves blockers[0..1] of
VERIFIER-REPORT-W24B-SHADOW.json.

## rt-clean-npm-1.0.0.tgz — sha256 0a95b713b40e41b3a4e44479663dc8ae5c8beb8066e76571d64942e44b73f3b5
Benign npm control: zero deps, zero lifecycle scripts, 3 packed files. Expected: PASS / rc0,
0 residue rows, install-delta non-empty (3). Cited by: this fix round's DONECLAIM (benign_live).

## rt_benign_local-1.0.0-py3-none-any.whl — sha256 01e73f38679ea44bb9ad02153fa620fc6c8e75fbe8416112cdda068dfd9b43d6
Benign zero-dependency pure wheel (PEP 427 quartet, hand-built zip). Proves the wheel local
lane's HONEST value — installability + benign-clean + exact-bytes identity — expected PASS/rc0,
0 rows. Cited by: this fix round's DONECLAIM (benign_live; replaces the untraceable 6620b266 sha).

## rt_plant_wheel-0.0.1-py3-none-any.whl — sha256 ef86383a06e703487cafb2e68fa8509d004cfa2b4607eacd4e1d89aefb6fb486
Inertness-confirmation plant: the exact shape the previous DONECLAIM falsely claimed flagged
HIGH (`.data/data/.config/evil.txt` + `.data/data/.config/systemd/user/evil.service`). Expected
verdict: PASS / rc0, 0 residue rows — pip (24.0 AND 25.0.1, verifier harness 2026-09-11; own
re-confirmation this round on python:3.12-slim/pip 25.0.1) records and prunes every path, so
the LOCAL wheel lane is residue-INERT by construction. Cited by: DONECLAIM
(inert_lane_evidence) + README doctrine paragraph + localArtifact.ts boundary comment.

## s1-hostile-plant/rt-shadow-plant-0.0.1.tar.gz — sha256 2734b50f1e8d291a016fd9104e6676105be062c49780aac49d143cd5ebc14f91
The shadow-laundering ATTACK sdist from verifier S1 live run (VERIFIER-REPORT-W24B-SHADOW.json
probes.S1_live: setup.py plants SP/traitlets-9.9.9.dist-info w/ RECORD claims incl ../-escape
orphan, real dep closure traitlets==5.16.1). Persisted from the verifier's own /tmp scratch by
root 2026-09-11 (its cleanup claim was incomplete — recorded in fix-round residuals). Kept as the
canonical repro of the launder-attempt the legitimacy stack must reject: expect ALL rows HIGH,
zero LOW demotions through current calibrate.ts.
