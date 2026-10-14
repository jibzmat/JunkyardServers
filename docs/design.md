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
- Networking: see M3 below.
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
- Console output: hosts send the last 64 KiB of each VM's serial log when it
  changes (and every 5 minutes); the leader keeps it in memory only.
- Metadata service: each host answers 169.254.169.254 for its own
  instances (see M3), identifying the caller by VPC and source address.
  IMDSv2 tokens are HMACs bound to the instance and its address.
- A host destroys VMs it no longer sees only after a minute, and the control
  plane serves host views only once a leader has applied the whole log, so
  a restart can't make a host wipe its VMs.

## Networking (M3)

Goal: EC2's VPC model. Tenants pick their own address ranges (they may
overlap between tenants), instances in one VPC reach each other on any PC,
nothing else reaches them unless a security group allows it, and
instances reach the internet through NAT.

- Records (Raft state): VPC (CIDR /16 to /28, a 24-bit VNI), subnet (CIDR
  inside its VPC), security group (in one VPC, ingress and egress rules
  whose source is a CIDR or another group). Each tenant gets a default VPC
  172.31.0.0/16 with a default subnet 172.31.0.0/20 and a default group,
  made on first use, as on EC2.
- IPAM: an instance's address comes from its subnet, chosen by the leader
  at launch (the first four addresses and the last are reserved, as on
  EC2: network, router, DNS, future, broadcast). The MAC is derived from
  the instance ID.
- On each PC, one network namespace per VPC that has instances there. It
  holds the VPC's routing table and firewall, so overlapping CIDRs of
  different tenants never meet, and conntrack is per VPC.
  - Instances are routed, not bridged: each tap is a point-to-point link
    with proxy ARP and a /32 route to its instance. Each subnet's router
    address (.1) is on the namespace's loopback, so the PC answers the
    guest's ARP for its gateway. Guests' MTU is 1370 (WireGuard
    and VXLAN headers).
  - Between PCs: a VXLAN device per VPC namespace (VNI = the VPC's), whose
    underlay is the WireGuard mesh, so traffic is encrypted between PCs. A
    remote instance is a /32 route via its PC's mesh address, with static
    neighbour and FDB entries; nothing is learned or flooded.
  - The PC accepts VXLAN only from PCs that run instances of that VPC (an
    iptables u32 match on outer source and VNI), so a PC can't inject
    traffic into a VPC it has no part in.
  - Internet: a veth pair from the namespace to the PC's own namespace,
    with NAT on both sides. Forwarding from the veth to the mesh, to other
    VPCs' veths or to private ranges on the PC's LAN is dropped.
  - Metadata: 169.254.169.254 is on the namespace's loopback, served by
    jyd through a socket opened inside the namespace, so the caller is
    known by (VPC, source address).
- Security groups: stateful (conntrack), enforced in the namespace's
  FORWARD chain on the PC that runs the instance, for both directions:
  established traffic is accepted, then an instance's egress rules on
  packets from its tap, its ingress rules on packets to its tap, and the
  rest dropped. A rule naming a group expands to the member instances' addresses,
  refreshed from the control plane (the whole ruleset is swapped with one
  iptables-restore). A host also drops packets from a tap
  whose source isn't the instance's (strict reverse-path filtering).
- The M2 scheme (one routed /24 of 10.128.0.0/9 per PC, all instances in
  one network) is removed. Instances are no longer reachable from the
  mesh; reaching them from outside the VPC (an Instance Connect Endpoint
  style tunnel, public IPs) comes with M5.

## Peer hardening (M4)

- Disk replicas: the scheduler gives every placed instance a replica, a
  second compute PC its placement allows with room to run it. The host
  mirrors the root disk and attached volumes there with QEMU's mirror job
  in write-blocking mode: after a first full copy, a guest write completes
  only once the copy has it too. The copy is a qcow2 on the replica served
  by qemu-nbd on a local socket; the two jyds carry the NBD stream over
  mutual TLS (port 7446, the replica accepts only the instance's current
  host). The host reports when every copy is in step.
- Failover: when a host has been gone for 2 minutes (as this leader sees
  it), each of its instances whose copies are in step moves to its
  replica, which boots it from the copy (running instances restart;
  stopped ones stay stopped), and a new replica is picked. Volumes whose
  copy wasn't in step stay on the lost PC, detached; detached volumes with
  a copy in step move too. An instance without a copy in step waits for
  its PC.
- A replica that dies stalls guest writes for at most about 15 seconds
  (a TCP user timeout of 10 s on the connection, then QEMU's 5 s NBD
  reconnect delay); the mirror then stops and the host retries with
  backoff, checking the replica answers first. A mirror restarted from
  scratch marks the copy out of step before it starts overwriting it.
- Fencing: once the instance has moved, the old replica refuses its old
  host's mirror connections, and the old host destroys the VM a minute
  after it rejoins and sees the instance gone. If the old host was only
  cut off, both copies ran for a while; that is the cost of not waiting
  longer.
- Not yet: incremental resync (a restart copies the whole disk again),
  choosing a new replica for a detached volume, and a copy on a third PC.

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
