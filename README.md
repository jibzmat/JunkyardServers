# Junkyard Servers

A peer-to-peer cloud made of spare x64 PCs that the stock `aws` CLI can drive
(`--endpoint-url`), starting with S3, EC2 and VPC networking. Storage, network
traffic and guest RAM are encrypted; PCs contributed by strangers only ever hold
ciphertext. Strangers' PCs get the same storage and compute features as your
own; the only difference is encrypted guest RAM, which needs SEV-SNP or TDX.

This repository is at **milestone M0: mesh and cluster bootstrap**. See
[docs/design.md](docs/design.md) for the architecture and roadmap.

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
internal/cluster/     shared types: roles, trust tiers
internal/hw/          hardware detection
```

## Tests

```sh
go vet ./... && go test -race ./...
```

## Not yet in M0

- Control nodes are added by hand; automatic placement across healthy
  trusted PCs (the decentralized control plane) comes later.
- NAT traversal and relaying have unit tests but have not yet run on real
  routers. At least one of your PCs needs a public address (or a forwarded
  UDP port, passed as `-wg-endpoint`) to act as a relay.
- Certificate rotation and revocation.

## License

[GNU Affero General Public License v3.0](LICENSE). If you run a modified
version as a network service, you must offer its users the source.
