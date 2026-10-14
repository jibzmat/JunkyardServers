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
  master key; master keys live in the control plane's Raft state and never
  leave it. Gateways ask the control plane to wrap and unwrap.
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
- M1 includes a gateway-side encrypted listing index for large buckets.
- A fully decentralized control plane is the goal: metadata split into many
  small Raft groups whose members are picked automatically from healthy
  owner-trusted PCs. M0 replicates the control plane with Raft across control
  nodes you add with `jyctl control add`; automatic placement comes later. Strangers'
  PCs without SEV-SNP/TDX never hold metadata keys or CA signing power.
- License: AGPL-3.0, so MinIO code (also AGPL-3.0) can be reused with
  attribution.
