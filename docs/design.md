# Design summary

The full design doc (with diagrams and discussion) lives in the project's
Claude Doc, "Junkyard Servers: Design Doc". This is the short version kept
next to the code.

## Principle

Storage and networking spread across many peers; compute runs only where data
can be decrypted safely. Encrypted shards can live on any PC. Plaintext in RAM
only lives on a PC the owner trusts, or one with attested AMD SEV-SNP or Intel
TDX.

## Trust tiers

| Tier | Who | May do |
| --- | --- | --- |
| `confidential` | attested SEV-SNP/TDX host (from M2) | run any tenant's guests |
| `trusted` | joined with a `-trusted` token (your PCs) | every role |
| `storage-only` | everyone else, including strangers' PCs | store ciphertext, relay |

Gossip is only trusted for liveness and current endpoints, because strangers
hold the gossip key too. Tier, roles, keys and mesh addresses always come from
the control plane registry.

## Roadmap

| Milestone | Scope | Exit test |
| --- | --- | --- |
| M0 Mesh and cluster | init/join, CA, WireGuard mesh, gossip, Raft core | 3 PCs talk over the mesh |
| M1 S3 storage | chunk, encrypt, 4+2 erasure coding, key service, SigV4 gateway, repair | `aws s3 sync` survives 2 PCs lost |
| M2 EC2 basics | microVMs, SEV-SNP/TDX attestation, trust-tier placement, volumes, AMIs | SSH into a launched VM |
| M3 VPC networking | VPCs, subnets, IPAM, VXLAN inside WireGuard, security groups | SGs enforced across PCs |
| M4 Peer hardening | proof-of-storage audits, reputation and quotas, restart on host loss | VM restarts on a new PC |
| M5 Scale out | cluster instances, live migration, NAT gateway, elastic IPs | one instance ID spans 4 PCs |
