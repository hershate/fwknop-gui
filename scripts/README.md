# scripts/ — fwknop fork helpers

## quickstart.sh — one-click startup / demo

Brings up a complete, self-contained fwknop system on the local host and proves
it works end to end: builds the project, mints matching keys, starts fwknopd
(pcap on loopback) + the operations WebUI, fires a real SPA packet from the
client, and verifies the iptables door opens (then expires).

```bash
./scripts/quickstart.sh            # demo (default): build + start + knock + verify
./scripts/quickstart.sh demo       # same as above
./scripts/quickstart.sh build      # ensure a pcap-enabled build exists
./scripts/quickstart.sh setup-sudo # narrow NOPASSWD sudo for fwknopd+iptables
./scripts/quickstart.sh knock 443  # send an SPA packet to open tcp/443
./scripts/quickstart.sh dashboard  # (re)start only the WebUI
./scripts/quickstart.sh status     # show fwknopd + dashboard status
./scripts/quickstart.sh stop       # stop fwknopd + dashboard
./scripts/quickstart.sh clean      # stop + remove the demo work dir
```

### What `demo` does

1. Builds fwknop/fwknopd/fwknopd-admin (pcap mode) if not already built.
2. Configures narrow passwordless sudo for `fwknopd` + `iptables` (asks for your
   sudo password once) so the backgrounded daemon can be managed.
3. Generates a fresh matching keypair into a work dir (default
   `/tmp/fwknop-quickstart`, override with `FWKNOPQS_WORK=...`).
4. Starts `fwknopd` (pcap on `lo`, UDP port 62201, structured audit on) and the
   `fwknop-dashboard` WebUI at http://127.0.0.1:8088 (if Go is installed).
5. Sends a real SPA packet (`tcp/22`) from the client and verifies the iptables
   `FWKNOP_INPUT` rule appears (`ACCEPT tcp dpt:22 /* _exp_<ts> */`).

After it is live:

| What | Where |
| --- | --- |
| WebUI | http://127.0.0.1:8088 |
| fwknopd log | `tail -f $WORK/fwknopd.log` |
| audit log | `tail -f $WORK/run/fwknopd_audit.log` |
| metrics | `cat $WORK/run/fwknopd.metrics` |
| open another door | `./scripts/quickstart.sh knock 443` |
| stop | `./scripts/quickstart.sh stop` |

### Requirements

- **Build**: `gcc make autoconf automake libtool pkg-config libpcap0.8-dev`
  (the script tells you if something is missing).
- **Runtime**: `sudo` (for iptables/fwknopd). The demo opens real iptables
  rules on loopback; it needs root for the firewall manipulation.
- **Optional**: `golang-go` (WebUI), `qrencode`/`zbarimg` (QR features).

### Environment overrides

- `FWKNOPQS_WORK` — work directory (default `/tmp/fwknop-quickstart`).
- `FWKNOPQS_DPORT` — SPA destination port (default `62201`).
- `FWKNOPQS_DASH_ADDR` — dashboard listen address (default `127.0.0.1:8088`).

### A note on the demo's security model

The demo binds everything to loopback and uses a 30-second firewall timeout. It
is intended to demonstrate the mechanism locally. For real remote protection,
deploy fwknopd with a proper `access.conf` (see
[`note/release/2.1.0.md`](../note/release/2.1.0.md)) — the demo's generated
`access.conf`/`fwknopd.conf` in `$WORK` are a good starting template.
