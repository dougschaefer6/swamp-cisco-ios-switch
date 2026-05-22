# @dougschaefer/cisco-ios-switch

A [Swamp](https://github.com/systeminit/swamp) extension model for managing a
Cisco IOS switch (e.g. Catalyst 2960) **over SSH** after it has been
bootstrapped at the console. It drives the interactive VTY the way an operator
would — disable the pager, optionally enter enable mode, push config, and
`write memory` — capturing the transcript and parsing device facts.

## What it does and does not do

This model **owns the switch after SSH is reachable**. It does **not** factory
reset the switch and **cannot** bootstrap SSH itself: a freshly wiped switch has
no IP and no VTY, so the first management config (hostname, domain, RSA key,
management IP, `transport input ssh`, a privilege-15 user) must be entered over
the **console**. Once the switch answers on its management IP, this model takes
over.

## Methods

| Method | Mutating | Description |
|--------|----------|-------------|
| `getRunningConfig` | no | Capture `show running-config` (secrets redacted by default) and `show version`; store the config file plus parsed model/IOS/uptime facts. |
| `runCommands` | no | Run arbitrary EXEC/show commands and capture their output. The verification surface (`show ip ssh`, `show ip route`, …). |
| `applyBaseline` | yes | Assert idempotent secure-access hardening: hostname/domain, `service password-encryption`, HTTP off, console + VTY login/timeout, SSH-only transport. Saves to startup. |
| `pushSnmp` | yes | Configure SNMPv2c read-only/read-write communities, location, contact, and an optional trap host from `globalArguments.snmp`. Saves to startup. |
| `pushRouting` | yes | Apply Layer-3 intent from `globalArguments.routing`: `ip routing`, VLANs/SVIs, a static default route, and access-port assignments. Saves to startup. |

Every mutating method accepts `dryRun=true` to render and store the exact IOS
lines **without connecting** — useful for review and for testing before the
switch is reachable.

## Pre-flight check

A `live`-labeled `switch-reachable` check TCP-probes the SSH port before
`applyBaseline`, `pushSnmp`, and `pushRouting`, failing fast if the switch is
unreachable. Skip it for an offline dry run with `--skip-check-label live`.

## Global arguments

| Key | Sensitive | Notes |
|-----|-----------|-------|
| `host` | | Management IP or hostname |
| `port` | | SSH port (default 22) |
| `username` | | A privilege-15 local user |
| `password` | yes | `${{ vault.get(asei, <switch>-admin) }}` |
| `enableSecret` | yes | Set **only** if the login does not land in privilege 15 |
| `hostname` / `domainName` | | Asserted by `applyBaseline` |
| `legacyAlgorithms` | | Append legacy SSH kex/cipher/host-key algorithms for old IOS (default true) |
| `commandTimeoutMs` | | Connect timeout + session read budget (default 20000) |
| `snmp` | partial | `readOnly`/`readWrite` (sensitive), `location`, `contact`, `trapHost` |
| `routing` | | `enabled`, `defaultRouteNextHop`, `vlans[]`, `accessPorts[]` |

### Example definition

```yaml
type: "@dougschaefer/cisco-ios-switch"
globalArguments:
  host: 10.20.0.10
  username: asei-admin
  password: ${{ vault.get(asei, sw-indy-mdf-admin) }}
  hostname: SW-INDY-MDF-01
  domainName: asei.local
  snmp:
    readOnly: ${{ vault.get(asei, sw-indy-mdf-snmp-ro) }}
    readWrite: ${{ vault.get(asei, sw-indy-mdf-snmp-rw) }}
    location: Indy MDF Rack 1
    contact: noc@asei.com
    trapHost: 10.20.0.50
  routing:
    enabled: true
    defaultRouteNextHop: 10.20.0.1
    vlans:
      - { id: 20, name: USER, sviIp: 198.51.100.1, sviMask: 255.255.255.0 }
      - { id: 30, name: AV,   sviIp: 203.0.113.1,  sviMask: 255.255.255.0 }
    accessPorts:
      - { range: "gigabitEthernet 1/0/1 - 12",  vlanId: 20, description: User Ports }
      - { range: "gigabitEthernet 1/0/13 - 24", vlanId: 30, description: AV/IoT Ports }
```

## Usage

```bash
# Create one definition per switch (or commit it as YAML — see above).
swamp model create "@dougschaefer/cisco-ios-switch" sw-indy-mdf \
  --global-arg host=10.20.0.10 \
  --global-arg username=asei-admin \
  --global-arg password='${{ vault.get(asei, sw-indy-mdf-admin) }}' \
  --global-arg hostname=SW-INDY-MDF-01 \
  --global-arg domainName=asei.local

# Review what would change without touching the switch (skip the live probe).
swamp model method run sw-indy-mdf applyBaseline --input dryRun=true --skip-check-label live

# Apply for real (the live reachability check runs first).
swamp model method run sw-indy-mdf applyBaseline --input dryRun=false
swamp model method run sw-indy-mdf pushSnmp     --input dryRun=false
swamp model method run sw-indy-mdf pushRouting  --input dryRun=false

# Verify, then capture a redacted running-config.
swamp model method run sw-indy-mdf runCommands --input 'commands=["show ip ssh","show ip route"]'
swamp model method run sw-indy-mdf getRunningConfig
```

## Transport notes

- Shells out to the system `ssh` client (OpenSSH ≥ 8.4) rather than bundling a
  JS SSH library — swamp bundles extensions with `deno bundle`, which can't
  resolve `ssh2`'s optional native addons. The login password is handed to
  `ssh` through a 0600 askpass helper, never on the command line.
- `legacyAlgorithms` (default on) appends `diffie-hellman-group1/14-sha1`,
  `ssh-rsa`/`ssh-dss` host keys, and CBC ciphers so old 2960 IOS images
  negotiate. It appends to — does not replace — modern algorithms.

## Security

- All credentials (`password`, `enableSecret`, SNMP communities) are
  vault-resolved and marked sensitive.
- `getRunningConfig` redacts community/secret/password/key lines by default
  (`redactSecrets=false` to keep them). `pushSnmp` stores redacted lines and
  suppresses device output.
- `runCommands` stores output **verbatim** — do not point it at
  `show running-config`/`show snmp` unless you intend to store the secrets it
  returns; use `getRunningConfig` (which redacts) instead.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
