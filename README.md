# Collector

Python portal plus a NetFlow probe. It watches exported flows, flags aggressive port scanners, and can SSH into a MikroTik to drop them on an address-list.

```
MikroTik 192.168.88.3:22232
        │  SSH (block / unblock)
        │  NetFlow v5 / v9 / IPFIX  →  UDP :2055
        ▼
   Collector host
        │
        └── Web portal  :8080
```

Default policy is **detect only**. Auto-block stays off until you enable it in the portal or set `AUTO_BLOCK=true`. The LAN allowlist (`192.168.88.0/24` by default) is never auto-blocked. Public DNS anycast (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9, OpenDNS) is always ignored, as are DNS/DoT **reply** legs (`src_port` 53/853) so NetFlow's reverse flows are not scored as scans.

## Run it

```bash
cd /root/collector
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# edit .env — portal password, MikroTik user/password or key
python -m collector
```

Open `http://<collector-ip>:8080` and sign in (`admin` / `changeme` until you change it).

To exercise the UI without live exports:

```bash
python -m collector --demo
```

## MikroTik: export NetFlow

Point **traffic-flow** at the collector, not at the router itself.

```
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=16k active-flow-timeout=30s inactive-flow-timeout=15s
/ip traffic-flow target
add dst-address=<COLLECTOR_IP> port=2055 version=9
```

RouterOS 7 also accepts IPFIX (`version=ipfix`). The probe understands v5, v9, and IPFIX.

UDP 2055 must be reachable from the router to the collector. If the collector is on the LAN, no extra NAT is required.

## Cisco: export NetFlow

The probe accepts **v5, v9, and IPFIX**. Prefer **v9** (or IPFIX on IOS-XE). Send UDP **2055** to `<COLLECTOR_IP>`. Sampling is optional; unsampled is better for scanner detection.

Cisco export is ingest-only. Auto-block still SSHs the MikroTik unless you add a separate IOS ACL workflow.

### IOS / IOS-XE — Flexible NetFlow (v9)

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

Junos calls this **J-Flow** (v5/v9) or **IPFIX**. Prefer **v9 or IPFIX**. Sampling is the usual MX/SRX pattern.

Templates must include IPv4/IPv6 addresses, L4 ports, protocol, and byte/packet counters — that is what the detector reads.

### MX / PTX — sampling to IPFIX

```
forwarding-options {
    sampling {
        instance COLLECTOR {
            input {
                rate 1;
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

For NetFlow v9 instead of IPFIX, use `version9 { template { ipv4; } }` on `flow-server` where the platform supports it. `rate 1` is every packet; raise the rate if the RE/PFE cannot keep up (scanner detection gets worse as sampling increases).

### SRX

Enable flow export on the zone/interfaces you care about (`forwarding-options sampling`; some releases also use `security forwarding-options`). Destination remains `<COLLECTOR_IP>` UDP **2055**.

Allow UDP/2055 from the exporter to the collector on any intermediate firewall.

## MikroTik: SSH blocking

The portal logs into `192.168.88.3` port `22232` (overridable in `.env`) and:

1. Adds/removes IPs on address-list `blocked-scanners` (timeout `1d` by default)
2. Ensures drop rules exist on `input` and `forward` for that list (IPv4 and IPv6)

Create a dedicated user if you do not want to use `admin`:

```
/user group add name=collector policy=ssh,read,write,test,sensitive
/user add name=collector group=collector password="choose-a-strong-password"
```

Confirm SSH is on 22232:

```
/ip service set ssh port=22232
/ip service print where name=ssh
```

Fill `.env`:

```
MIKROTIK_HOST=192.168.88.3
MIKROTIK_PORT=22232
MIKROTIK_USER=collector
MIKROTIK_PASSWORD=...
```

Or use a key with `MIKROTIK_KEY_PATH=/path/to/id_ed25519`. Then use **Test SSH** on the portal.

Manual block/unblock from the UI talks to the same address-list. Enabling **Auto-block on MikroTik** pushes detections as they fire.

## Detector

Inside a sliding window (default 30s) a source is flagged when it does any of:

| Kind | Default |
| --- | --- |
| Vertical | ≥ 40 destination ports against one host |
| Horizontal | ≥ 40 hosts on one destination port |
| Spray | ≥ 80 unique destination ports overall |
| Connect-storm | ≥ 40 source ports against one host:service (HTTPS floods) |

Reply legs from well-known service ports (443, 80, 22, 53, …) to ephemeral client ports are ignored so NetFlow reverse flows do not look like scans from your own servers. `PROTECTED_CIDRS` (default `151.244.12.0/27`) is never auto-blocked.

Thresholds and the allowlist are editable on the portal (Thresholds) and persist in SQLite (`data/collector.db`). Public DNS resolvers and protected WAN prefixes stay allowlisted even if you edit that field.

## systemd

```bash
sudo mkdir -p /opt/collector
sudo cp -a . /opt/collector
# install venv + .env as above
sudo cp deploy/collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now collector
```

Health check: `GET /api/health` (no auth). The dashboard APIs require a session.

## JSON dumps (API key)

`SECRET_KEY` in `.env` is the API access key. Talker counters reset when the process restarts; blocked IPs come from the local DB plus the MikroTik address-list.

```bash
# combined blocked IPs + top talkers
curl -sS -H "X-API-Key: $SECRET_KEY" http://<collector-ip>:8080/api/dump

# split
curl -sS -H "X-API-Key: $SECRET_KEY" http://<collector-ip>:8080/api/dump/blocked
curl -sS -H "X-API-Key: $SECRET_KEY" 'http://<collector-ip>:8080/api/dump/talkers?limit=50'
```

Also accepted: `Authorization: Bearer <SECRET_KEY>` or `?key=<SECRET_KEY>`.

OpenAPI: [http://192.168.88.20:8080/docs](http://192.168.88.20:8080/docs) — Authorize with `X-API-Key`. CORS preflight (`OPTIONS`) is enabled for GET dumps.

Drop-in FastAPI client for another app: `examples/fastapi_client.py`

```python
from examples.fastapi_client import router
app.include_router(router)
# COLLECTOR_URL=http://192.168.88.20:8080
# COLLECTOR_API_KEY=<SECRET_KEY>
```

## Layout

| Path | Role |
| --- | --- |
| `collector/probe.py` | UDP NetFlow listener |
| `collector/netflow.py` | v5 / v9 / IPFIX parser |
| `collector/detection.py` | scan detector |
| `collector/mikrotik.py` | RouterOS SSH |
| `collector/app.py` | FastAPI portal |
| `collector/templates/` | login + dashboard |
