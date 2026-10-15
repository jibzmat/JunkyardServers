# Junkyard Servers

A peer-to-peer cloud made of spare x64 PCs that the stock `aws` CLI can drive
(`--endpoint-url`), starting with S3, EC2 and VPC networking. Storage, network
traffic and guest RAM are encrypted; PCs contributed by strangers only ever hold
ciphertext. Strangers' PCs get the same storage and compute features as your
own; the only difference is encrypted guest RAM, which needs SEV-SNP or TDX.

This repository has finished **M0 (mesh and cluster bootstrap)**, **M1
(encrypted S3 storage)**, **M3 (VPC networking)** and **M4 (peer
hardening)**, and has **M2 (EC2)** except SEV-SNP/TDX attestation: the stock
`aws s3`, `aws s3api` and `aws ec2` commands work against it. See [docs/design.md](docs/design.md) for the
architecture and roadmap.

## What M0 does

- `jyctl init` creates a cluster on the first PC: an Ed25519 cluster CA, the
  control plane, a gossip key and an admin credential.
- `jyctl token` issues a join token. Tokens pin the CA by fingerprint, are
  single-use and expire (24h by default). `-trusted` marks the PC as yours.
- `jyctl join <token>` enrolls a PC. Without `-trusted` it joins as
  **untrusted**: it stores encrypted shards and runs compute like any other
  PC, but never holds cluster keys, so it can't run the control plane or a
  gateway. Instances only land on it if their owner picks placement `any`,
  because without memory encryption the host could read guest RAM. SEV-SNP/TDX
  claims are ignored until attestation arrives in M2.
- `jyd` runs on every PC: it serves the control plane API on the PC that ran
  `init`, gossips liveness over encrypted SWIM (hashicorp/memberlist), and keeps
  a WireGuard interface (`jy0`, `100.64.0.0/10`) in sync with every other node.
- `jyctl members` and `jyctl wg-config` show the cluster and this node's mesh
  config.
- PCs behind home routers find their public address from their peers
  (endpoint reflection) and advertise it in gossip, so two PCs behind NAT can
  punch through to each other. When a direct WireGuard handshake doesn't come
  up within 45 seconds (strict NAT on both sides), traffic is routed through
  one of your trusted PCs with a public address, and a direct path is retried
  every 5 minutes. Relays are owner-trusted only, because relayed mesh packets
  are decrypted and re-encrypted on the relay.
- The control plane is replicated with Raft (over mutual TLS) across any of
  your trusted PCs: `jyctl control add` turns one into a control node. Any
  control node answers reads and redirects writes to the leader, and nodes
  fail over between control addresses on their own.

## What M1 adds: S3

- Storage nodes (any tier) run a shard server. Gateways (your trusted PCs)
  serve the S3 API on port 9000.
- Every object, and every part of a multipart upload, gets its own random
  key. It is cut into 4 MiB chunks, each sealed with XChaCha20-Poly1305 and
  Reed-Solomon coded (4 data + 2 parity with 6 or more storage nodes, fewer
  on small clusters) onto different PCs. Storage nodes only see ciphertext
  shards named by their SHA-256.
- Object keys are wrapped by a per-tenant master key held by the control
  plane, which also keeps buckets, objects and uploads in its Raft state.
- Tenant master keys are stored sealed by a cluster key-encryption key that
  is never written down: it is Shamir-split across the control nodes, a
  majority of which rebuild it in memory at startup. Neither a Raft snapshot
  nor one control node's disk is enough to read tenant keys (except with a
  single control node). The key is rotated whenever control nodes are added
  or removed.
- The gateway checks SigV4 (headers, presigned URLs, signed and unsigned
  streaming uploads, checksums, Content-MD5) and legacy SigV2.
- Supported: list/create/delete/head bucket, get bucket location, put, get
  (with ranges and conditional headers), head, delete, copy, multi-delete,
  ListObjects v1 and v2, and multipart uploads including part copy. Anything
  else (ACLs, policies, versioning, tagging) answers `NotImplemented`.
- Repair runs on the control-plane leader. When a storage PC has been
  unreachable for 15 minutes (`jyd -repair-after`), every chunk it held is
  rebuilt from any k surviving shards and the missing shards are written to
  other PCs. Repair works on ciphertext and needs no keys.
- Storage PCs re-read every shard daily and drop any that rotted; the next
  repair pass writes it back. Shards nothing refers to (a failed upload, a
  PC that returns after repair moved its shards) are deleted after 24 hours.
- Objects written while few PCs were up (say 1+1 coding on two PCs) are
  re-coded to the stronger coding once more PCs join, up to 1 GiB per pass.
- A chunk is written once k+1 of its shards are stored, so one more PC can
  fail before it is at risk. Reads need any k shards. A PC that fails a write
  is skipped for 30 seconds, so uploads keep working while gossip catches up.

```sh
sudo bin/jyctl tenant create alice      # prints an access key and secret
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://192.168.1.10:9000 s3 mb s3://photos
aws --endpoint-url http://192.168.1.10:9000 s3 sync ~/Pictures s3://photos/
```

## What M2 adds: EC2

```sh
aws s3 cp noble-server-cloudimg-amd64.img s3://images/noble.img
aws ec2 register-image --name noble --image-location images/noble.img
aws ec2 create-key-pair --key-name me --key-type ed25519 \
    --query KeyMaterial --output text > me.pem
aws ec2 run-instances --image-id ami-… --instance-type t3.small --key-name me
aws ec2 describe-instances --query 'Reservations[].Instances[].PrivateIpAddress'
# on the PC running it (see M3 for why):
sudo ip netns exec jy-vpc-… ssh -i me.pem ubuntu@172.31.0.4
```

(all with `--endpoint-url http://<gateway>:9000`)

- Instances are QEMU VMs with KVM on PCs holding the compute role. Images
  are any qcow2 or raw cloud image registered from S3; the bytes are copied,
  encrypted and erasure-coded like any object, and cached on each host.
- Supported: run, describe (with filters), stop, start, reboot, terminate,
  describe-instance-status, key pairs (create, import, describe, delete),
  register/describe/deregister images, create-image from an instance,
  volumes (create, attach, detach, delete, describe), snapshots (create,
  delete, describe, and volumes restored from them), tags, regions, zones
  and instance types (t3, m5, c5, r5 sizes), get-console-output. `aws ec2
  wait` works.
- The instance metadata service answers at 169.254.169.254 (IMDSv1 and
  IMDSv2 tokens): instance ID, type, addresses, placement, public keys,
  tags, user data and the identity document. Each PC serves its own
  instances, and a VM can't forge another's address to read its data.
- cloud-init gets the key pair, user data and a static address in its
  VPC subnet (see M3).
- Placement is the `jy:placement` tag: `private` (default: your PCs),
  `any` (strangers' PCs too) or `confidential` (SEV-SNP/TDX, once
  attestation lands). A launch no PC can take fails with
  InsufficientInstanceCapacity.
- A shutdown from inside the guest stops the instance, as on EC2. Root
  disks are local to the PC; they survive stop and start.
- Volumes attach and detach while the instance runs (PCIe hotplug, up to 8
  per instance) and show up in the guest as
  `/dev/disk/by-id/virtio-vol…`. A volume lives on the PC of the instance
  it was first attached to; to move it, snapshot it and create a new
  volume from the snapshot. Snapshots and images made with create-image
  are stored in the cluster, encrypted and erasure-coded like objects.
  Making one pauses the guest for the copy (create-image without
  `--no-reboot` shuts it down and restarts it, as EC2 does).
- Compute PCs need `qemu-system-x86_64`, `qemu-img`, `qemu-nbd`, `genisoimage` (or
  `mkisofs`/`xorriso`), `iproute2` (with the `vxlan` kernel module) and
  `iptables`. `jyd -emulate` runs guests
  without KVM, very slowly, for trying things out.

## What M3 adds: VPCs and security groups

```sh
aws ec2 create-vpc --cidr-block 10.0.0.0/16
aws ec2 create-subnet --vpc-id vpc-… --cidr-block 10.0.1.0/24
aws ec2 create-security-group --group-name web --description web --vpc-id vpc-…
aws ec2 authorize-security-group-ingress --group-id sg-… --protocol tcp --port 22 --cidr 10.0.0.0/16
aws ec2 run-instances … --subnet-id subnet-… --security-group-ids sg-…
```

- Each tenant gets a default VPC (172.31.0.0/16), default subnet
  (172.31.0.0/20) and default security group on first use, as on EC2, so
  plain `run-instances` works. Address ranges of different tenants may
  overlap.
- Supported: create/describe/delete VPCs, subnets and security groups,
  authorize and revoke ingress and egress rules (CIDRs and group
  references), `--subnet-id`, `--security-group-ids`/`--security-groups`
  and `--network-interfaces` on launch, and the vpc-id, subnet-id and
  group-id filters. Addresses are allocated from the subnet (first four and
  last reserved).
- Each PC keeps one network namespace per VPC it runs instances of, so
  tenants' networks never meet. Instances in one VPC reach each other on
  any PC through VXLAN carried inside the WireGuard mesh, and a PC accepts
  a VPC's VXLAN traffic only from PCs running instances of it.
- Security groups are stateful and enforced on the PC running the
  instance, in both directions, across PCs. A guest can't use an address
  other than its own.
- Instances reach the internet through NAT on their PC, but not the mesh,
  other VPCs or the PC's LAN.
- Instances have no address outside their VPC yet. To log in, run `ssh`
  inside the VPC's namespace on the PC that runs the instance, as above
  (`sudo ip netns list` shows them). A tunnel through the gateway and
  public IPs come with M5.

## What M4 adds: peer hardening

- Every instance's disks (root and attached volumes) are mirrored live to
  a second compute PC its placement allows. A write finishes in the guest
  only once both PCs have it.
- If an instance's PC is gone for 2 minutes, the instance restarts on
  that second PC from the copy, keeping its ID, address and data, and a
  new second PC is picked. Volumes come along.
- Compute PCs exchange disk copies on TCP port 7446 (`jyd -replica-port`,
  the same on every PC), over mutual TLS inside the mesh. They need
  `qemu-nbd`.
- Proof of storage: every storage PC is asked for a random shard it should
  hold every 10 minutes and must send it back intact. PCs that keep
  failing are suspended (no new data or instances, their shards rebuilt
  elsewhere) until passing audits restore their score, or you vouch for
  one with `jyctl reinstate <node>`. `jyctl members` shows each PC's
  audits.
- Quotas: `jyd -storage-quota 500G` caps what a PC stores, and every PC
  keeps 10% of its disk (up to 20 GiB) free. New shards go to your own
  PCs first, so with enough of them every chunk can be read even if all
  strangers' PCs disappear at once.

## What M5 adds so far: live migration, elastic IPs and NAT gateways

- `jyctl migrate <instance-id>` moves a running instance to its second PC
  (the one holding the live copy of its disks) without stopping it: the
  guest keeps its uptime, memory, open connections and address, and
  pauses for well under a second at the end. `-to <node>` picks another
  PC; its disks are copied there first.
- `jyctl drain <node>` moves every running instance off a PC that way and
  gives it no new instances or copies, say before you shut it down;
  `jyctl undrain <node>` undoes it.
- The two PCs need compatible CPUs (guests run with the host's CPU
  model).
- Elastic IPs: list the public addresses your PCs can take traffic for
  (`jyctl public-ip add <node> <ip>...`: extra addresses a provider
  routes to a PC, such as a VPS's additional IPs, or spare ones on its
  LAN). Tenants then use them as on AWS:

  ```sh
  aws ec2 allocate-address
  aws ec2 associate-address --allocation-id eipalloc-... --instance-id i-...
  ssh ubuntu@<the public address>
  ```

  The instance can run on any PC: the PC holding the address passes its
  traffic both ways over the VPC, and the instance's own traffic to the
  internet leaves from the address too. `DescribeInstances` and the
  metadata service show it. Terminating the instance frees the address;
  `release-address` returns it to the pool.
- NAT gateways and route tables: a private subnet's instances reach the
  internet from one elastic IP, wherever they run, and can't be reached
  from it:

  ```sh
  aws ec2 create-nat-gateway --subnet-id subnet-<public> --allocation-id eipalloc-...
  aws ec2 create-route-table --vpc-id vpc-...
  aws ec2 create-route --route-table-id rtb-... --destination-cidr-block 0.0.0.0/0 --nat-gateway-id nat-...
  aws ec2 associate-route-table --route-table-id rtb-... --subnet-id subnet-<private>
  ```

  Every VPC has a main route table and an internet gateway from the
  start (`describe-route-tables`, `describe-internet-gateways`); its
  default route sends traffic out through each instance's own PC, as
  before. A table without a default route, or one to a deleted NAT
  gateway (a blackhole), gives its subnets no internet. An instance's
  own elastic IP wins over its subnet's NAT gateway.
- Still to come in M5: cluster instances.

## Try it

Needs Go 1.25+, Linux, and for the mesh: root plus the `wireguard` kernel
module and `iproute2`.

```sh
go build -o bin/ ./cmd/...

# PC 1 (192.168.1.10)
sudo bin/jyctl init -control 192.168.1.10:7443
sudo bin/jyd &
sudo bin/jyctl token            # a stranger's PC: untrusted
sudo bin/jyctl token -trusted   # one of your own PCs

# PC 2
sudo bin/jyctl join 'jy1.…'
sudo bin/jyd &
sudo bin/jyctl members

# Make PC 2 a control node too (it must have joined with a -trusted token)
sudo bin/jyctl control add -api 192.168.1.11:7443
# then restart jyd on PC 2
sudo bin/jyctl control list
```

Run 3 or 5 control nodes: Raft needs a majority alive, so 2 control nodes
tolerate no failures and 3 tolerate one.

`jyd -wireguard=false` skips the kernel interface (useful for testing without
root); `jyctl wg-config` prints the config that would be applied.

State lives in `/var/lib/junkyard` (override with `-dir` or `JY_DIR`). Private
keys and the node config are written with mode 0600.

## Layout

```
cmd/jyd/              node daemon
cmd/jyctl/            admin CLI
internal/pki/         cluster CA and certificates
internal/token/       join tokens
internal/control/     control plane API, IP allocation, state
internal/node/        node identity and config on disk
internal/membership/  encrypted gossip (liveness only)
internal/mesh/        WireGuard mesh
internal/agent/       jyd main loop
internal/storage/     object encryption, erasure coding, placement, shard servers
internal/s3meta/      S3 metadata types (tenants, buckets, objects, uploads)
internal/s3gw/        S3 and EC2 gateway: SigV4/SigV2, buckets, objects, multipart, EC2 Query API
internal/ec2meta/     EC2 records (instances, key pairs, images, volumes, snapshots)
internal/compute/     compute host: QEMU driver, volumes, snapshots, cloud-init seed, metadata
internal/vnet/        VPC namespaces, VXLAN, routing, NAT and security group rules on a PC
internal/repair/      rebuilds shards lost with storage PCs, audits storage PCs
internal/shamir/      Shamir secret sharing
internal/cluster/     shared types: roles, trust tiers
internal/hw/          hardware detection
```

## Tests

```sh
go vet ./... && go test -race ./...
```

## Not yet done

M2:

- A volume on a PC that never comes back, without a copy in step, can't
  be deleted yet.
- SEV-SNP/TDX attestation, so `confidential` placement has no hosts yet.
- Spot, launch templates, IAM instance profiles (the metadata service has
  no credentials to hand out yet).

M5:

- A migration that can't finish (a guest dirtying memory faster than the
  network carries it, even slowed down) gives up after 30 minutes.
- The console output from before a migration stays on the old PC.
- Right after a migration, other PCs can't reach the instance for a few
  seconds, until they see where it went.
- An elastic IP or NAT gateway works only while the PC holding its
  address is up, and instances can't reach their own VPC's elastic IPs
  from inside it.
- Route tables hold only the default route (0.0.0.0/0); traffic inside
  the VPC always stays local. Private NAT gateways, and associating a
  table with a gateway, aren't supported.

M4:

- Chunks stored before you had enough trusted PCs aren't rebalanced onto
  them later.
- Suspension is the only consequence of failing audits; nothing yet
  limits how many strangers' PCs one person can join (Sybil resistance).
- After any interruption a mirror copies the whole disk again (no
  incremental resync yet), and the copy is out of step meanwhile.

M3:

- Network ACLs, VPC peering and extra network interfaces answer
  `InvalidAction`. (Route tables and NAT gateways came in M5; creating
  or attaching internet gateways isn't needed, as every VPC has one.)
- IPv6.
- Internet NAT is untested here (the test machine had no internet).

M1:

- Object names are plaintext in the control plane's state, which only your
  trusted PCs hold. Encrypting them, with gateways building the listing
  index, waits until metadata moves to PCs that don't hold keys.

From M0:

- Control nodes are added by hand; automatic placement across healthy
  trusted PCs (the decentralized control plane) comes later.
- NAT traversal and relaying have unit tests but have not yet run on real
  routers. At least one of your PCs needs a public address (or a forwarded
  UDP port, passed as `-wg-endpoint`) to act as a relay.
- Certificate rotation and revocation.

## License

[GNU Affero General Public License v3.0](LICENSE). If you run a modified
version as a network service, you must offer its users the source.
