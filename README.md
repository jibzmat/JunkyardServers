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
```

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

- The control plane is a single PC with a JSON state file; the 3-5 node Raft
  group comes next.
- NAT traversal and relays for PCs that can't reach each other directly.
- Certificate rotation and revocation.

## License

[GNU Affero General Public License v3.0](LICENSE). If you run a modified
version as a network service, you must offer its users the source.
