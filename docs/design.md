# Design summary

The full design doc (with diagrams and discussion) lives in the project's
Claude Doc, "Junkyard Servers: Design Doc". This is the short version kept
next to the code.

## Principle

Every PC, including strangers' PCs, offers the same storage and compute
features. The one thing hardware decides is whether guest RAM is hidden from
the host owner: that needs AMD SEV-SNP or Intel TDX. Storage shards are always
ciphertext, so storage needs no trust at all.

## Trust tiers

| Tier | Who | Storage | Compute | Control plane, gateway |
| --- | --- | --- | --- | --- |
| `trusted` | joined with a `-trusted` token (your PCs) | yes | yes | yes |
| `confidential` | stranger's PC with attested SEV-SNP/TDX (from M2) | yes | yes, RAM encrypted | no |
| `untrusted` | any other stranger's PC | yes | yes, RAM visible to host | no |

The control plane and gateways hold the CA key, key-service shares and every
tenant's data keys, so they stay on owner-trusted PCs. That is infrastructure,
not a user feature: tenants get every feature whichever PCs they use.

## Placement

Each instance has a placement (EC2 tag or launch option, from M2):

| Placement | Runs on | Use for |
| --- | --- | --- |
| `confidential` | hosts with SEV-SNP/TDX only | secrets, regulated data |
| `private` (default) | your PCs or confidential hosts | normal workloads |
| `any` | every compute host, including untrusted | public builds, rendering, tests, anything not secret |

Gossip is only trusted for liveness and current endpoints, because strangers
hold the gossip key too. Tier, roles, keys and mesh addresses always come from
the control plane registry.

## Storage (M1)

- Data path: client → gateway (SigV4) → per-object (or per-part) random
  XChaCha20-Poly1305 key → 4 MiB chunks, each sealed with nonce = random
  prefix || chunk index and additional data = object ID || chunk index →
  Reed-Solomon k+m shards → rendezvous-hashed onto distinct storage nodes.
- k+m is chosen from the number of live storage nodes: 4+2 with 6 or more,
  down to 1+1 with two. A chunk counts as written with k+1 shards stored.
- Key hierarchy: object keys are wrapped with AES-256-GCM by the tenant's
  master key. Master keys are kept in the Raft state sealed by a cluster
  key-encryption key (KEK) and never leave the control plane; gateways ask it
  to wrap and unwrap.
- The KEK is never stored. The leader Shamir-splits it, majority threshold,
  across the Raft voters, sealing each share to that node's X25519 key
  (share.key, local only); the sealed shares and a check value are in Raft.
  A control node opens its own share and fetches the rest from peers over
  mutual TLS. The leader rotates the KEK, re-sealing every tenant key in the
  same Raft write, whenever the voter set changes. Tenants created before
  this existed are sealed on the next rotation.
- Metadata (tenants, access keys, buckets, objects with shard layouts,
  multipart uploads) lives in the Raft state machine. Overwrites and deletes
  return the old record so the gateway deletes its shards.
- Shard servers accept reads and writes from any cluster certificate (shards
  are ciphertext named by hash) but deletes only from control nodes and
  trusted gateways. Clients check the server certificate against the node's
  mesh IP, which WireGuard binds to the node's key.
- Repair: the control leader tracks when each storage node was last alive.
  After 15 minutes gone, it rebuilds each affected chunk from k shards
  (decode, re-encode; coding is deterministic so hashes match) onto nodes
  holding no shard of that chunk, and records the moves in one Raft write
  per segment. The write is refused if the object changed meanwhile, and the
  new shards are then deleted.
- Scrubbing: each storage node re-reads every shard daily (and on every
  read) and deletes any whose hash no longer matches. The leader lists each
  live node's shards on every repair pass, so a shard a live node lost is
  rebuilt and written back to that node.
- Upgrades: segments coded with fewer parity shards than the live node
  count allows are re-coded (sealed chunks are re-coded without keys) and
  swapped in with one Raft write that is refused if the layout changed.
- Garbage collection: the same pass deletes shards no object or unfinished
  upload refers to, once they are 24 hours old and have been unreferenced
  for 15 minutes (so downloads that started before a re-code finish).
  Inventories are listed hourly, not on every pass. Shards are written before
  their object is recorded, so younger ones may belong to an upload in
  flight. Nodes are listed before metadata is read, so a shard recorded
  after the read is never older than the listing says.

## Compute (M2)

- EC2 Query API on the gateway port, told apart from S3 by the signature's
  service (`ec2`). Instances, key pairs and images are in the Raft state.
- Images: RegisterImage copies an S3 object (qcow2 or raw) into a hidden
  `_images` bucket, so the bytes are encrypted and erasure-coded and repair,
  re-coding and GC cover them. Control nodes stream an image to a compute
  host only while it runs an instance of it.
- Scheduler (control leader): pending instances go to the least-loaded live
  compute host the placement allows (`private`: trusted or confidential
  tiers; `any`: all; `confidential`: confidential tier) with room: vCPUs
  overcommitted 4x, memory not overcommitted, 1 GiB left for the host. A
  pending instance on a host gone for 2 minutes is rescheduled.
- Hosts poll for their instances, run them as daemonised QEMU processes
  (surviving jyd restarts) with a qcow2 overlay on the cached image and a
  cloud-init NoCloud seed (key pair, user data, static network config),
  and report state changes; the control plane accepts only transitions a
  host may make.
- Networking: each compute host gets a /24 of 10.128.0.0/9 on first use,
  served on a bridge (host = .1), routed to it over WireGuard (the subnet is
  in the peer's AllowedIPs) and NATed for traffic leaving the cluster.
- Volumes: a qcow2 file on one compute host, chosen when the volume is
  first attached (the instance's host); attachments are attaching →
  attached → detaching, moved along by host reports. Hosts give each VM 8
  PCIe root ports and hotplug volumes with QMP (`blockdev-add`,
  `device_add`), serial = volume ID. Detach waits for the guest to release
  the device.
- Snapshots and CreateImage are tasks in the Raft state for the host holding
  the disk. The host pauses the VM (which flushes its writes), copies the
  disk to a standalone qcow2, resumes, and streams it to a control node,
  which stores it as an object in the hidden `_snapshots` or `_images`
  bucket and completes the task. Tasks on a host gone for 2 minutes fail.
- A host destroys VMs it no longer sees only after a minute, and the control
  plane serves host views only once a leader has applied the whole log, so
  a restart can't make a host wipe its VMs.

## Roadmap

| Milestone | Scope | Exit test |
| --- | --- | --- |
| M0 Mesh and cluster | init/join, CA, WireGuard mesh, gossip, Raft core | 3 PCs talk over the mesh |
| M1 S3 storage | chunk, encrypt, 4+2 erasure coding, key service, SigV4 gateway, repair | `aws s3 sync` survives 2 PCs lost |
| M2 EC2 basics | microVMs, SEV-SNP/TDX attestation, placement (`confidential`/`private`/`any`), volumes, AMIs | SSH into a launched VM |
| M3 VPC networking | VPCs, subnets, IPAM, VXLAN inside WireGuard, security groups | SGs enforced across PCs |
| M4 Peer hardening | proof-of-storage audits, reputation and quotas, restart on host loss | VM restarts on a new PC |
| M5 Scale out | cluster instances, live migration, NAT gateway, elastic IPs | one instance ID spans 4 PCs |

## Decisions

- Strangers' PCs are supported from v1 with full storage and compute features.
- None of the first PCs have SEV-SNP or TDX, so placement `any` is available
  from the start.
- Listing large buckets: each bucket's keys are kept in a sorted B-tree in
  the control plane's state, so a page of 1000 keys costs O(log n + 1000)
  and common prefixes are skipped over rather than walked (about 5 ms for
  two pages of a million-key bucket). Names are plaintext there because
  control nodes already hold tenant keys; the gateway-side encrypted index
  comes with moving metadata to PCs that don't.
- A fully decentralized control plane is the goal: metadata split into many
  small Raft groups whose members are picked automatically from healthy
  owner-trusted PCs. M0 replicates the control plane with Raft across control
  nodes you add with `jyctl control add`; automatic placement comes later. Strangers'
  PCs without SEV-SNP/TDX never hold metadata keys or CA signing power.
- License: AGPL-3.0, so MinIO code (also AGPL-3.0) can be reused with
  attribution.
