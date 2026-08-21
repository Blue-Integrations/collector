# Collector

Python portal plus a NetFlow probe. It watches exported flows, flags aggressive port scanners, and can SSH into a **MikroTik**, **Cisco IOS/XE**, or **Juniper Junos** box to drop them on an access list. Pick the flavor on the dashboard.

```
Exporter (MikroTik / Cisco / Juniper)
        │  NetFlow v5 / v9 / IPFIX  →  UDP :2055
        ▼
   Collector host  :8080
        │
        └── SSH block/unblock → chosen router
```

Default policy is **detect only**. Auto-block stays off until you enable it in the portal or set `AUTO_BLOCK=true`. CIDRs in `ALLOWLIST` (LAN and management) are never auto-blocked. Public DNS anycast (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9, OpenDNS) is always ignored, as are DNS/DoT **reply** legs (`src_port` 53/853) so NetFlow's reverse flows are not scored as scans.

## Portal dashboard

Sign in at `http://<collector-ip>:8080`. The main view includes:

| Area | What it shows |
| --- | --- |
| **Records (10s)** | Flow records received in the last 10 seconds (`flows_last_10s`) |
| **Flows received** | Total records since startup |
| **Active scanners** | Detections after live filters (see below) |
| **Blocked on router** | IPs on the router access list |

**Detected scanners** and **Router access list** are collapsible panels (click the header). They start collapsed so **Recent sampled flows** stays visible. Count badges on each header update every 2 seconds.

### Live filters

Filters apply to both **Detected scanners** and **Recent sampled flows** without reloading:

| Filter | Applies to |
| --- | --- |
| Protocol (TCP / UDP / ICMP / ICMPv6) | Flows |
| Detection kind | Detections |
| Dst port | Horizontal / connect-storm detections; all flows |
| Protected dst only | Traffic whose destination is in `PROTECTED_CIDRS` |
| SYN only | TCP flows with SYN set (`tcp_flags`) |
| Hide blocked / Hide allowlisted | Both tables (on by default) |

Use **Protocol → ICMP** to focus on ICMP in the flows table. Use **Kind → ICMP flood** or **Large flow** after those detections fire.

Other controls: **Router** vendor picker (MikroTik / Cisco / Juniper), **Auto-block**, **Test SSH**, **Thresholds** (detector tuning + self-upgrade), **Webhooks** (Slack / Discord chat notifications), manual block/unblock, WHOIS on access-list IPs (click or Alt+click).

### Webhooks (Slack / Discord)

Open **Webhooks** in the header (left of **Sign out**). Paste an [incoming Slack webhook](https://api.slack.com/messaging/webhooks) or [Discord webhook](https://discord.com/developers/docs/resources/webhook) URL, choose whether to notify on **detections** and/or **blocks**, then **Save**. Use **Test Slack** / **Test Discord** before relying on alerts.

| `.env` variable | Default | Purpose |
| --- | --- | --- |
| `SLACK_WEBHOOK_URL` | *(empty)* | Default Slack URL (portal overrides in SQLite) |
| `DISCORD_WEBHOOK_URL` | *(empty)* | Default Discord URL |
| `WEBHOOK_NOTIFY_DETECTIONS` | `true` | Post when a scanner / flood is detected |
| `WEBHOOK_NOTIFY_BLOCKS` | `true` | Post when an IP is blocked on the router |

Each `(source IP, detection kind)` and each blocked IP is limited to **one chat message every 5 minutes** so floods do not spam the channel. Failed webhook delivery is logged in the portal event log.

**Restart required:** after changing Python code, restart the collector process (or `systemctl restart collector`). A restart started from inside Cursor's sandbox may not bind port 8080 on the host — use `./startcollector.sh` or systemd on the machine itself.

## Run it

### First install

```bash
cd /path/to/collector
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# edit .env — portal password, then SSH for the router you will block on
```

### Start

From the install directory:

```bash
./startcollector.sh
```

The script loads `.venv`, reads `.env`, and runs `python -m collector`. Pass CLI flags through if needed (e.g. `./startcollector.sh --demo` for synthetic traffic).

Open `http://<collector-ip>:8080` and sign in (`admin` / `changeme` until you change it).

## Capacity and bandwidth

The collector is **not in the data path**. User, web, and WAN traffic is routed or switched elsewhere. Only **NetFlow / IPFIX export** reaches the host: small UDP datagrams on port **2055** from the exporter.

| Traffic | Through collector? |
| --- | --- |
| Monitored production traffic | **No** |
| NetFlow / IPFIX export | **Yes** (UDP :2055) |

Export volume is usually far below line rate. Exporters send **flow records** (5-tuple + byte/packet counters), not a copy of every packet. Rough guide:

- **~1–5% of monitored traffic** if export is aggressive and unsampled
- **Much less** with MikroTik cache/timeouts or Juniper/Cisco sampling

Example: **1 Gbps** monitored might produce **~10–50 Mbps** of export in a heavy case, often **under a few Mbps** with normal cache settings.

### What this process can handle

One Python asyncio process parses UDP and runs scan detection. Internal limits from the code:

| Limit | Value | Effect |
| --- | --- | --- |
| Flow queue | 20,000 records | Overflow increments `dropped` — those flows skip detection |
| Flow samples in SQLite | every 8th flow | Keeps the dashboard readable |
| Router SSH probe | every 20s | Block list sync, not per-packet |

For a **single edge router** exporting to a LAN collector, **hundreds to a few thousand flow records per second** is comfortable. It is not built as a carrier-grade collector for many high-volume exporters at unsampled line rate.

### What to watch

Dashboard metrics or `GET /api/dump` (API key):

- **`flows_last_10s`** — flow records received in the last 10 seconds
- **`flows_per_sec`** — average records/s over that same sliding window
- **`dropped`** — queue full; detection is missing events
- **`parse_errors`** — bad or missing v9/IPFIX templates

If **`dropped` stays at 0** and scans look sane, export bandwidth is not your bottleneck. Scale by **flow record rate**, not Gbps of production traffic.

NetFlow export is **bursty** (exporter cache timeouts, often 15–30s on MikroTik). The dashboard polls every 2 seconds, so **Records (10s)** can jump in steps rather than ticking smoothly — that is normal.

### Export sizing by line rate

Size for **flow record rate** (what the collector ingests), not monitored Gbps. This process is comfortable around **500–3,000 records/s** on one edge exporter; the internal queue holds **20,000** records before `dropped` increments.

Scaled from the 1 Gbps example above (~**10–50 Mbps** aggressive export, **~1–5 Mbps** with sane cache/sampling):

| Monitored line (busy) | Aggressive export (unsampled / 1:1-ish) | Recommended export (cache + sampling) |
| --- | --- | --- |
| **1 Gbps** | ~10–50 Mbps UDP | ~1–5 Mbps |
| **10 Gbps** | ~100–500 Mbps (will overwhelm this collector) | ~5–25 Mbps |
| **25 Gbps** | ~250 Mbps–1.2 Gbps | ~10–50 Mbps |
| **100 Gbps** | multi-Gbps | ~25–100 Mbps (often needs a dedicated collector) |

Rough **Records (10s)** on the dashboard (same traffic mix, order-of-magnitude):

| Line | Aggressive | Recommended |
| --- | --- | --- |
| **1 G** | 5k–50k+ (bursty) | **500–5,000** |
| **10 G** | 50k+ / `dropped` | **2,000–8,000** |
| **25 G** | `dropped` | **3,000–12,000** |
| **100 G** | `dropped` | **5,000–20,000** (at ceiling — sample harder) |

If **`dropped` > 0**, increase sampling, export fewer interfaces, or shorten inactive timeouts. Scanner detection degrades as sampling gets coarser — balance export volume vs visibility.

### Shared export rules (all vendors)

1. Export **WAN / internet-facing interfaces only** — not every VLAN on a core.
2. **Active flow timeout ≈ 30s** — aligns with default `SCAN_WINDOW_SEC=30`.
3. **Inactive timeout ≈ 15s** — closes idle flows without filling cache.
4. Include **TCP flags** in the template where the platform allows (portal **SYN only** filter).
5. **Higher line rate → more sampling** (Cisco/Juniper); MikroTik has no packet sampler — use interface scope and cache size.

### Quick pick by tier

| Tier | Strategy |
| --- | --- |
| **1 G** | MikroTik WAN-only, 30s/15s, 16k cache — usually no sampling |
| **10 G** | Cisco/Juniper **1:1024–4096** on WAN ingress, 30s active cache |
| **25 G** | **1:4096–16384**, watch `dropped`, consider a beefier collector VM |
| **100 G** | **1:16384+**, multiple collectors or commercial flow analytics; this app targets **edge 1–10G** |

Vendor-specific examples: [MikroTik](#mikrotik-export-netflow), [Cisco](#cisco-export-netflow), [Juniper](#juniper-export-j-flow--ipfix).

## Upgrade

The collector can update itself from a git checkout (`git pull --ff-only` + `pip install -e .`). Manual installs without git are supported too.

**Requirements:** `git`, network access to the remote, and `pip` for the same Python that runs the portal (venv or system). The upgrade user must be able to write the install directory.

### CLI (recommended for production)

```bash
cd /root/collector   # or /opt/collector
source .venv/bin/activate   # if you use a venv

# see whether origin is ahead (contacts remote)
python3 -m collector upgrade --check

# check local state only (offline)
python3 -m collector upgrade --check --no-fetch

# pull, pip install -e .
python3 -m collector upgrade

# pull on a specific branch
python3 -m collector upgrade --branch main

# after copying files by hand (no git)
python3 -m collector upgrade --no-git

# reinstall deps only
python3 -m collector upgrade --no-git --no-install   # noop on deps
python3 -m collector upgrade --no-install            # pull only, skip pip

# run a restart command when finished (or set UPGRADE_RESTART_CMD in .env)
python3 -m collector upgrade --restart "systemctl restart collector"
```

| Flag | Meaning |
| --- | --- |
| `--check` | Report version / git commit; do not change anything |
| `--no-fetch` | With `--check`, compare without contacting the remote |
| `--no-git` | Skip `git pull` (manual tree copy) |
| `--no-install` | Skip `pip install -e .` |
| `--remote` | Git remote (default: `UPGRADE_GIT_REMOTE` or `origin`) |
| `--branch` | Git branch (default: current branch or `UPGRADE_GIT_BRANCH`) |
| `--restart` | Shell command after upgrade (default: `UPGRADE_RESTART_CMD`) |

`--check` exit codes: **0** up to date, **2** update available, **1** error.

Example check output:

```
version: 0.1.0
root:    /opt/collector
git:     main @ f54e109
remote:  origin
status:  3 commit(s) behind origin/main
behind:  3 (a1b2c3d)
```

### `.env`

```
UPGRADE_GIT_REMOTE=origin
UPGRADE_GIT_BRANCH=main
UPGRADE_RESTART_CMD=systemctl restart collector
UPGRADE_ALLOW_API=true
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPGRADE_GIT_REMOTE` | `origin` | Remote to fetch/pull |
| `UPGRADE_GIT_BRANCH` | *(current branch)* | Branch to pull; empty = stay on checked-out branch |
| `UPGRADE_RESTART_CMD` | *(empty)* | Run after a successful upgrade (systemd, docker, etc.) |
| `UPGRADE_ALLOW_API` | `true` | Allow portal/API upgrade buttons |

Set `UPGRADE_ALLOW_API=false` to disable in-portal upgrades (CLI still works).

### Portal

Open **Thresholds** → version line at the bottom:

- **Check updates** — calls the same logic as `upgrade --check`
- **Upgrade now** — `git pull` + `pip install -e .`; runs `UPGRADE_RESTART_CMD` when set

Requires a signed-in session. The running process must be restarted (manually or via `UPGRADE_RESTART_CMD`) before new Python code is loaded.

### HTTP API (session auth)

Dashboard session cookie (same as the UI), not the dump API key:

```bash
# check for updates
curl -sS -b "collector=<session-cookie>" http://<collector-ip>:8080/api/upgrade/status

# run upgrade (optional JSON body)
curl -sS -X POST -b "collector=<session-cookie>" \
  -H "Content-Type: application/json" \
  -d '{"restart": true, "git": true, "install": true}' \
  http://<collector-ip>:8080/api/upgrade
```

Returns installed version, git commit, commits behind, and upgrade log lines.

### systemd install

After [first install](#first-install), register the service from the install directory:

```bash
sudo ./establishsystemd.sh
```

The script writes `/etc/systemd/system/collector.service` with this checkout’s paths, runs as the install directory owner, reloads systemd, and `enable --now`s the unit. Use `--no-start` to install the unit without starting it.

Typical production upgrade loop:

```bash
sudo systemctl stop collector
cd /path/to/collector && source .venv/bin/activate
python3 -m collector upgrade
sudo systemctl start collector
```

Or set `UPGRADE_RESTART_CMD=systemctl restart collector` in `.env` and run `python3 -m collector upgrade` from the portal or CLI — the service restarts itself when the upgrade finishes.

Manual installs without git: copy the new tree over the install directory, then `python3 -m collector upgrade --no-git`.

## MikroTik: export NetFlow

Point **traffic-flow** at the collector, not at the router itself. RouterOS has **no packet sampler** — control export volume with **which interfaces** you export, **cache size**, and **timeouts**.

### 1 Gbps edge (typical)

Export **one WAN interface** (not `interfaces=all` on a busy box):

```
/ip traffic-flow
set enabled=yes interfaces=<WAN_IF> cache-entries=16384 \
    active-flow-timeout=30s inactive-flow-timeout=15s
/ip traffic-flow target
add dst-address=<COLLECTOR_IP> port=2055 version=9
```

Expected: **Records (10s)** ~500–3,000; export **~1–5 Mbps** UDP.

RouterOS 7 also accepts IPFIX (`version=ipfix`). The probe understands v5, v9, and IPFIX.

### By line rate

| Line | `cache-entries` | Interfaces | Notes |
| --- | --- | --- | --- |
| **1 G** | 16k | WAN only | Sweet spot for this collector |
| **10 G** | 32k | WAN only | If **Records (10s)** > ~8k, narrow interfaces or shorten inactive timeout |
| **25 G** | 32k–64k | WAN only | Consider upstream sampling on a core switch/router |
| **100 G** | — | Do not rely on MikroTik alone | Use a sampled exporter on core hardware |

UDP **2055** must be reachable from the router to the collector. If the collector is on the LAN, no extra NAT is required.

## Cisco: export NetFlow

The probe accepts **v5, v9, and IPFIX**. Prefer **v9** (or IPFIX on IOS-XE). Send UDP **2055** to `<COLLECTOR_IP>`.

Cisco export is ingest-only until you set `CISCO_*` in `.env` and select **Cisco** on the dashboard. Then auto-block SSHs that box and maintains an object-group + ACL.

### Sampling by line rate

| Line | Sampler `1 out-of N` | Typical export UDP |
| --- | --- | --- |
| **1 G** | none (optional 128) | ~1–5 Mbps |
| **10 G** | **1024–4096** | ~5–20 Mbps |
| **25 G** | **4096–16384** | ~10–40 Mbps |
| **100 G** | **16384–65536** | ~25–100 Mbps |

Apply the monitor on **WAN ingress** (and egress if you need reply-leg visibility). Unsampled is best for scanner detection on a **1 G** edge; add a sampler from **10 G** up.

### IOS / IOS-XE — Flexible NetFlow (v9), 1 Gbps

```
flow record COLLECTOR-REC
 match ipv4 protocol
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 match interface input
 collect counter bytes
 collect counter packets
 collect transport tcp flags
!
flow exporter COLLECTOR-EXP
 destination <COLLECTOR_IP>
 transport udp 2055
 export-protocol netflow-v9
 source <EXPORT_INTERFACE>
!
flow monitor COLLECTOR-MON
 record COLLECTOR-REC
 exporter COLLECTOR-EXP
 cache timeout active 30
 cache timeout inactive 15
!
interface GigabitEthernet0/0
 ip flow monitor COLLECTOR-MON input
 ip flow monitor COLLECTOR-MON output
```

### IOS / IOS-XE — 10 Gbps+ with sampler

```
sampler COLLECTOR-SAMP mode random 1 out-of 4096
!
flow monitor COLLECTOR-MON
 record COLLECTOR-REC
 exporter COLLECTOR-EXP
 cache timeout active 30
 cache timeout inactive 15
 sampler COLLECTOR-SAMP
!
interface TenGigabitEthernet0/0/0
 ip flow monitor COLLECTOR-MON input
```

Raise `out-of` toward **16384** on **25 G** and **65536** on **100 G** if **Records (10s)** or `dropped` climb.

IPv6: duplicate the record with `ipv6` matches, or add a second monitor.

### Older IOS — original NetFlow (v5)

```
ip flow-export version 5
ip flow-export destination <COLLECTOR_IP> 2055
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15
interface GigabitEthernet0/0
 ip route-cache flow
```

NX-OS uses `feature netflow` plus `flow exporter` / `flow monitor` — same idea: exporter UDP 2055, v9, 5-tuple + bytes/packets.

## Juniper: export J-Flow / IPFIX

Junos calls this **J-Flow** (v5/v9) or **IPFIX**. Prefer **v9 or IPFIX**. **`input { rate N; }`** means sample **1 in N packets** for new flow keys.

Templates must include IPv4/IPv6 addresses, L4 ports, protocol, and byte/packet counters — that is what the detector reads.

### Sampling `rate` by line rate

| Line | `input rate` (1:N) | Notes |
| --- | --- | --- |
| **1 G** | **100–500** (or `rate 1` on quiet SRX edges) | `rate 1` = heaviest export |
| **10 G** | **1000–4096** | WAN sampling only |
| **25 G** | **4096–16384** | |
| **100 G** | **16384–100000** | Often PFE sampling + dedicated collector |

Apply `sampling { input; output; }` on **WAN interface units** only.

### MX / PTX — 1 Gbps example (IPFIX)

```
forwarding-options {
    sampling {
        instance COLLECTOR {
            input {
                rate 100;
            }
            family inet {
                output {
                    flow-server <COLLECTOR_IP> {
                        port 2055;
                        version-ipfix {
                            template {
                                ipv4;
                            }
                        }
                    }
                    inline-jflow {
                        source-address <ROUTER_LO0>;
                    }
                }
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                sampling {
                    input;
                    output;
                }
            }
        }
    }
}
```

For NetFlow v9 instead of IPFIX, use `version9 { template { ipv4; } }` on `flow-server` where the platform supports it. Raise `rate` (coarser sampling) as line rate increases — see table above.

### SRX

Enable flow export on the zone/interfaces you care about (`forwarding-options sampling`; some releases also use `security forwarding-options`). Destination remains `<COLLECTOR_IP>` UDP **2055**.

Allow UDP/2055 from the exporter to the collector on any intermediate firewall.

## MikroTik: SSH blocking

The portal logs into the router over SSH (host and port from `.env`) and:

1. Adds/removes IPs on address-list `blocked-scanners` (timeout `1d` by default)
2. Ensures one IPv4 `chain=forward` drop for that list (added once; not reordered later)
3. Removes tracked connections from a newly blocked IP (`src-address=` / `dst-address=` exact match on RouterOS 7+) so existing TCP sessions die immediately

IPv6 filter is not managed. Packets only evaluate rules for their chain, so extra `input` / `forward-in` drops never see forwarded WAN traffic. Bridged L2 with `use-ip-firewall=no` can bypass IP filter on hairpinned VLAN traffic — not the usual routed WAN ingress path.

Create a dedicated user if you do not want to use `admin`:

```
/user group add name=collector policy=ssh,read,write,test,sensitive
/user add name=collector group=collector password="choose-a-strong-password"
```

Confirm SSH is reachable on the port you configure:

```
/ip service print where name=ssh
```

Fill `.env`:

```
MIKROTIK_HOST=<ROUTER_IP>
MIKROTIK_PORT=22
MIKROTIK_USER=collector
MIKROTIK_PASSWORD=...
```

Or use a key with `MIKROTIK_KEY_PATH=/path/to/id_ed25519`. Leave `BLOCKER_VENDOR=mikrotik` (or pick **MikroTik** on the portal) and use **Test SSH**.

Manual block/unblock from the UI talks to the same address-list. Enabling **Auto-block on router** pushes detections as they fire.

## Cisco: SSH blocking (IOS / IOS-XE)

Fill `.env`, pick **Cisco** on the dashboard, then **Test SSH**.

```
CISCO_HOST=192.0.2.1
CISCO_PORT=22
CISCO_USER=collector
CISCO_PASSWORD=...
CISCO_ENABLE_PASSWORD=...
CISCO_ACL=NETFLOW-COLLECTOR
CISCO_OBJECT_GROUP=blocked-scanners
```

The collector creates `object-group network blocked-scanners` and extended ACL `NETFLOW-COLLECTOR`:

```
deny ip object-group blocked-scanners any
permit ip any any
```

It does **not** apply the ACL to an interface. Do that once on the WAN yourself:

```
interface GigabitEthernet0/0
 ip access-group NETFLOW-COLLECTOR in
```

NX-OS object-groups use different syntax and are not driven by this client.

## Juniper: SSH blocking (Junos)

Fill `.env`, pick **Juniper**, then **Test SSH**.

```
JUNIPER_HOST=192.0.2.2
JUNIPER_PORT=22
JUNIPER_USER=collector
JUNIPER_PASSWORD=...
JUNIPER_PREFIX_LIST=blocked-scanners
JUNIPER_FILTER=NETFLOW-COLLECTOR
```

The collector `commit`s a prefix-list plus filter `NETFLOW-COLLECTOR` (`source-prefix-list` → `discard`, then `accept`). It does **not** attach the filter to an interface. Apply it on the ingress family:

```
set interfaces ge-0/0/0 unit 0 family inet filter input NETFLOW-COLLECTOR
commit
```

## Detector

Inside a sliding window (default **30s**) a source is flagged when it crosses any threshold below. Only **TCP and UDP** participate in port-scan logic; **ICMP** and **oversized flows** use separate counters.

| Kind | Default threshold | What it catches |
| --- | --- | --- |
| **Vertical** | ≥ 40 destination ports on one host | Port scan on a single target |
| **Horizontal** | ≥ 40 hosts on one destination port | Sweep one port across many hosts |
| **Spray** | ≥ 80 unique destination ports | Wide port spray |
| **Connect-storm** | ≥ 40 source ports → one host:service | HTTPS/TCP floods (many ephemeral src ports to :443, etc.) |
| **ICMP flood** | ≥ 50 ICMP/ICMPv6 flows in the window | High-volume ping / ICMP noise |
| **Large flow** | ≥ 20 flows with ≥ **2048 bytes** each | Jumbo pings, fat flows, repeated large datagrams |

Reply legs from well-known service ports (443, 80, 22, 53, …) to ephemeral client ports are ignored so NetFlow reverse flows do not look like scans or large-flow abuse from your own servers. Prefixes in `PROTECTED_CIDRS` (your WAN and hosted services) are never auto-blocked.

**ICMP note:** the flows table **Bytes** column is NetFlow's **per-flow byte counter**, not guaranteed single-packet size. A row showing 4126 B may be one large ICMP datagram or many smaller packets aggregated before the exporter closed the flow. MikroTik maps ICMP type/code into the L4 port fields on ICMP rows.

### Thresholds (`.env` or portal **Thresholds**)

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCAN_WINDOW_SEC` | `30` | Sliding window for all kinds |
| `VERTICAL_PORT_THRESHOLD` | `40` | Vertical scan |
| `HORIZONTAL_HOST_THRESHOLD` | `40` | Horizontal scan |
| `UNIQUE_PORT_THRESHOLD` | `80` | Spray |
| `ICMP_FLOOD_THRESHOLD` | `50` | ICMP flows per source in the window |
| `LARGE_FLOW_MIN_BYTES` | `2048` | Minimum bytes per flow to count toward large-flow |
| `LARGE_FLOW_THRESHOLD` | `20` | Large flows per source in the window |
| `ALLOWLIST` | *(see `.env.example`)* | CIDRs never auto-blocked (LAN, collector, etc.) |
| `PROTECTED_CIDRS` | *(see `.env.example`)* | Your public/hosted prefixes — sources there are not scored |

Connect-storm reuses `VERTICAL_PORT_THRESHOLD` for its source-port count. Thresholds persist in SQLite (`data/collector.db`) when changed from the portal. Public DNS resolvers and protected WAN prefixes stay allowlisted even if you edit the allowlist field.

## systemd

After [first install](#first-install):

```bash
sudo ./establishsystemd.sh
```

That installs `deploy/collector.service` into `/etc/systemd/system/` with the correct `WorkingDirectory`, `.env`, and venv Python for **this** tree (works in `/opt/collector`, a home checkout, or anywhere you cloned it). The service runs as the owner of the install directory.

Useful commands:

```bash
sudo systemctl status collector
sudo journalctl -u collector -f
sudo systemctl restart collector
```

For manual runs (no systemd), use `./startcollector.sh` from the install directory.

Health check: `GET /api/health` (no auth). The dashboard APIs require a session.

After the first install, use [Upgrade](#upgrade) to pull new releases (`python3 -m collector upgrade` or the portal **Thresholds** panel).

## JSON dumps (API key)

`SECRET_KEY` in `.env` is the API access key. Talker counters reset when the process restarts; blocked IPs come from the local DB plus the active router access list.

```bash
# combined blocked IPs + top talkers
curl -sS -H "X-API-Key: $SECRET_KEY" http://<collector-ip>:8080/api/dump

# split
curl -sS -H "X-API-Key: $SECRET_KEY" http://<collector-ip>:8080/api/dump/blocked
curl -sS -H "X-API-Key: $SECRET_KEY" 'http://<collector-ip>:8080/api/dump/talkers?limit=50'
```

Also accepted: `Authorization: Bearer <SECRET_KEY>` or `?key=<SECRET_KEY>`.

OpenAPI: `http://<collector-ip>:8080/docs` — Authorize with `X-API-Key`. CORS preflight (`OPTIONS`) is enabled for GET dumps.

Drop-in FastAPI client for another app: `examples/fastapi_client.py`

```python
from examples.fastapi_client import router
app.include_router(router)
# COLLECTOR_URL=http://<collector-ip>:8080
# COLLECTOR_API_KEY=<SECRET_KEY>
```

## Layout

| Path | Role |
| --- | --- |
| `startcollector.sh` | Activate venv and start the collector (foreground) |
| `establishsystemd.sh` | Install/refresh `collector.service` for this directory |
| `deploy/collector.service` | systemd unit template (`@INSTALL_ROOT@` placeholders) |
| `collector/probe.py` | UDP NetFlow listener |
| `collector/netflow.py` | v5 / v9 / IPFIX parser |
| `collector/detection.py` | Scan, ICMP flood, and large-flow detector |
| `collector/mikrotik.py` | RouterOS SSH |
| `collector/cisco.py` | IOS/XE object-group + ACL |
| `collector/juniper.py` | Junos prefix-list + filter |
| `collector/webhooks.py` | Slack / Discord notification delivery |
| `collector/app.py` | FastAPI portal |
| `collector/upgrade.py` | git pull + pip self-upgrade |
| `collector/templates/` | login + dashboard |
