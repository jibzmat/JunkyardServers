# Junkyard Servers

A peer-to-peer cloud made of spare x64 PCs that the stock `aws` CLI can drive
(`--endpoint-url`), starting with S3, EC2 and VPC networking. Storage, network
traffic and guest RAM are encrypted; PCs contributed by strangers only ever hold
ciphertext. Strangers' PCs get the same storage and compute features as your
own; the only difference is encrypted guest RAM, which needs SEV-SNP or TDX.

This repository has finished **M0 (mesh and cluster bootstrap)** and has the
core of **M1 (encrypted S3 storage)**: the stock `aws s3` and `aws s3api`
commands work against it. See [docs/design.md](docs/design.md) for the
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
- A chunk is written once k+1 of its shards are stored, so one more PC can
  fail before it is at risk. Reads need any k shards. A PC that fails a write
  is skipped for 30 seconds, so uploads keep working while gossip catches up.

```sh
sudo bin/jyctl tenant create alice      # prints an access key and secret
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://192.168.1.10:9000 s3 mb s3://photos
aws --endpoint-url http://192.168.1.10:9000 s3 sync ~/Pictures s3://photos/
```

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
internal/s3gw/        S3 gateway: SigV4/SigV2, buckets, objects, multipart
internal/repair/      rebuilds shards lost with storage PCs
internal/shamir/      Shamir secret sharing
internal/cluster/     shared types: roles, trust tiers
internal/hw/          hardware detection
```

## Tests

```sh
go vet ./... && go test -race ./...
```

## Not yet done

M1:

- Scrubbing and garbage collection: shards are not yet re-read to catch
  silent corruption, and shards left on a PC that comes back after repair
  are not cleaned up.
- Objects written while PCs were down keep the thinner coding that fit the
  PCs left; repair restores missing shards but doesn't upgrade the coding.
- The gateway-side encrypted listing index for large buckets. Listing works
  today from the control plane's state.
- A gateway reads the control addresses it had at start; restart it after
  adding or removing control nodes.

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
