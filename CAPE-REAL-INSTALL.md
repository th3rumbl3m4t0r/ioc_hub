# Standing up a real CAPEv2 and wiring it to IoCHub

This is the "heavy" path: a genuine CAPEv2 sandbox that detonates samples in a
Windows guest VM, with IoCHub driving it over REST. Budget **half a day to a
day**, most of it on the Windows analysis guest. Basic Linux + virtualization
experience assumed.

---

## 0. The two hard constraints (read first)

1. **CAPE runs on Ubuntu, not Rocky.** CAPE's automated installer supports
   **Ubuntu 20.04 / 22.04 / 24.04 LTS** only (it is apt-based and Ubuntu-specific).
   It will *not* install on your Rocky 10 box. So CAPE has to live on an Ubuntu
   host, and IoCHub (on Rocky) points at it over the network. This is fine —
   IoCHub was built to talk to CAPE over REST, it doesn't need CAPE local.

2. **CAPE needs hardware virtualization + a Windows guest.** It boots a real
   Windows 10 VM per detonation via KVM/QEMU. That means VT-x/AMD-V, and if
   CAPE itself runs inside a VM, **nested virtualization**.

### Pick a topology

- **A — Dedicated Ubuntu host for CAPE (recommended).** A second machine (bare
  metal is happiest) or a cloud VM that exposes nested virt. IoCHub on Rocky →
  `url = http://<cape-host>:8000`. Simplest and most reliable.

- **B — One box: Ubuntu VM on your Rocky host.** Run an Ubuntu 22.04 guest under
  KVM on the Rocky box; CAPE inside it runs the Windows guest → **two levels of
  nesting** (Rocky KVM → Ubuntu → CAPE's Windows). Works on a dev box if nested
  virt is enabled; expect slow analyses. IoCHub and CAPE end up on the same
  physical machine but different OSes.

Everything below installs CAPE on the **Ubuntu** host/VM (call it the *CAPE
host*), then wires IoCHub from the Rocky box.

---

## 1. Prerequisites & virtualization check

On the intended CAPE host:

```bash
# CPU virtualization present?
egrep -c '(vmx|svm)' /proc/cpuinfo          # >0 expected

# If CAPE runs inside a VM (topology B), nested virt must be ON at the level
# ABOVE it. On the Rocky KVM host:
cat /sys/module/kvm_intel/parameters/nested   # Y or 1   (AMD: kvm_amd)
# enable persistently if needed:
#   echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm.conf
#   sudo modprobe -r kvm_intel && sudo modprobe kvm_intel
# and give the Ubuntu guest CPU mode "host-passthrough".
```

Resourcing: **16 GB RAM / 4+ vCPU / 100+ GB disk** is comfortable; 8 GB/4 vCPU
is the painful floor (the Windows guest alone wants ~50 GB and 2+ vCPU).

---

## 2. Install CAPE on the Ubuntu host

CAPE ships an installer; **expect rough edges** — the upstream scripts often
have a few errors at any given time, so read the output and the repo's current
installer README. Shape of it:

```bash
# As a sudo-capable user on the Ubuntu host:
sudo apt update && sudo apt -y install git
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2/installer        # (installer scripts live here in current layout)

# Edit the installer variables near the top of cape2.sh:
#   NETWORK_IFACE=virbr0           # the libvirt default bridge
#   IFACE_IP=192.168.122.1         # that bridge's host IP
#   PASSWD=<postgres password for the 'cape' DB user>
#   USER=cape
nano cape2.sh

# 1) Hypervisor + deps (installs KVM/QEMU + virt-manager). Reboot after.
sudo ./kvm-qemu.sh all $(whoami) 2>&1 | tee kvm-qemu.log
sudo reboot

# 2) CAPE itself (Python stack via poetry, PostgreSQL, systemd units, etc.).
cd CAPEv2/installer
sudo ./cape2.sh base 2>&1 | tee cape2-base.log
sudo reboot
```

After this you'll have `/opt/CAPEv2` owned by user `cape`, a PostgreSQL `cape`
database, and these **systemd services**:

- `cape.service` — scheduler/host
- `cape-processor.service` — report processing
- `cape-web.service` — Django web UI **and REST API on :8000**
- `cape-rooter.service` — network rooter (routing for guests)

```bash
sudo systemctl enable --now cape cape-processor cape-rooter cape-web
systemctl status cape-web        # API should be listening on 127.0.0.1:8000
```

---

## 3. Build the Windows analysis guest (the real work)

This part is manual, GUI-driven, and needs a **licensed Windows 10 ISO**. High
level (follow a current CAPE Windows-guest guide for the fiddly bits):

1. In **virt-manager**, create a Windows 10 VM on the `default` (virbr0) network.
   Give it 2+ vCPU, 4+ GB RAM, ~60 GB disk.
2. Install Windows. Then **disable** Windows Update, Defender/SmartScreen, the
   firewall, UAC nags, and sleep/hibernate — you want a static, quiet victim.
3. Install the **CAPE agent**: copy `/opt/CAPEv2/agent/agent.py` into the guest
   and set it to run at startup (e.g. as a scheduled task / startup entry,
   pythonw so no console). It listens for the host to push the analyzer.
4. Give the guest a **static IP** on the virbr0 subnet (e.g. 192.168.122.50),
   gateway 192.168.122.1, and confirm the host can reach the agent port.
5. Optionally install common runtime bait (browsers, Office viewer, etc.) so
   malware behaves.
6. **Snapshot** the running guest (clean, agent running). Note the snapshot name.
7. Register the VM in CAPE: edit `/opt/CAPEv2/conf/kvm.conf` (machine label, IP,
   snapshot, platform=windows). Set the matching `machinery = kvm` and result
   server IP in `/opt/CAPEv2/conf/cuckoo.conf`.

Restart `cape` services after editing conf. A good smoke test is to submit
EICAR or a benign exe from the CAPE **web UI** at `http://<cape-host>:8000` and
watch it run to a report. Get the sandbox working *in the UI first* — only then
wire IoCHub.

---

## 4. Configure CAPE's REST API for IoCHub  ← the integration-critical step

Edit `/opt/CAPEv2/conf/api.conf`. IoCHub needs token auth on, the rate limit
**off**, and the endpoints it calls enabled:

```ini
[api]
# IoCHub authenticates with a DRF token.
token_auth_enabled = yes
# REQUIRED: IoCHub polls every 5s (~12/min). The default 5/min throttle will
# otherwise reject it with HTTP 429 mid-analysis.
ratelimit = no
# If you must keep ratelimit on, raise the limits instead:
#   default_user_ratelimit = 1000/m

# Enable the four endpoints IoCHub uses (section names per your api.conf;
# several endpoints ship disabled by default):
[tasksearch]
enabled = yes
[taskcreate]
enabled = yes
[taskstatus]
enabled = yes
[taskreport]
enabled = yes
```

Create a token for IoCHub to present:

```bash
cd /opt/CAPEv2/web
# one-time admin (interactive):
sudo -u cape poetry run python3 manage.py createsuperuser
# mint a REST token for that user — copy the value it prints:
sudo -u cape poetry run python3 manage.py drf_create_token <user>
```

Restart the API: `sudo systemctl restart cape-web`.

> Security: keep CAPE on a private network. It exists to run live malware — do
> **not** expose :8000 to the internet. IoCHub reaching it over a LAN/VPN/WG link
> is the right shape.

---

## 5. Verify CAPE REST directly (before involving IoCHub)

From the CAPE host (and again from the Rocky box, to prove reachability):

```bash
U=http://<cape-host>:8000
T=<the DRF token>

# reachable at all (any code, even 401, means "up"):
curl -s -o /dev/null -w 'apiv2 root: %{http_code}\n' "$U/apiv2/"

# token works + the endpoints IoCHub calls answer:
curl -s -H "Authorization: Token $T" "$U/apiv2/tasks/list/"            | head -c 300; echo
curl -s -H "Authorization: Token $T" "$U/apiv2/tasks/search/sha256/44d88612fea8a8f36de82e1278abb02f/"; echo
```

If `tasks/list` returns JSON (not a 401/429/HTML login), you're good. A 401
means token/`auth_only`; a 429 means you didn't turn off `ratelimit`.

---

## 6. Wire IoCHub (on the Rocky box)

Edit `/opt/iochub/data/cape.conf`. **Recommended:** leave `spawn` empty and just
point IoCHub at the already-running CAPE — CAPE is best run as its own persistent
systemd services, not as a child of IoCHub.

```ini
enabled = true
# Empty: do NOT have IoCHub spawn CAPE. It drives the persistent CAPE over REST.
spawn =
url = http://<cape-host>:8000
token = <the DRF token from step 4>
# set to 1 only if you front CAPE with self-signed HTTPS
insecure = 0
idle_timeout = 28800
[allow]
.*
```

Why empty `spawn`: with no spawn command IoCHub never tries to launch or kill
CAPE, so (a) you don't need to relax the hardened `iochub.service` or add
sudoers, and (b) the 8-hour idle reaper won't touch CAPE (it only reaps things
IoCHub spawned). CAPE stays up, managed by its own services.

`cape.conf` is re-read on every request, so no IoCHub restart is needed — just
save it and click **detonate (CAPE)** on a file entity.

### If you really want IoCHub to own CAPE's lifecycle (not recommended for real CAPE)

Set `spawn` to a launcher (e.g. `sudo -n systemctl start cape cape-processor cape-rooter cape-web`)
and relax `iochub.service` per its `### CAPE` block (`NoNewPrivileges=false`,
a sudoers rule for the iochub user, etc.). Caveat: the idle reaper kills the
*spawned* process group, which for a `systemctl start` is just the short-lived
client — it won't cleanly stop CAPE — so lifecycle ownership is illusory here.
Persistent services + empty `spawn` is the correct model.

---

## 7. End-to-end from IoCHub

1. Add or open a **file** entity (upload ≤32 MB to detonate the bytes, or use a
   known hash to look up / submit).
2. Click **detonate (CAPE)** → it should return immediately and show a "running"
   ring; you can keep working.
3. When CAPE finishes, you get a notification; reopen the file → **view CAPE
   results** → tick contacted domains/IPs/URLs and dropped files → add to graph.

---

## 8. Troubleshooting

| Symptom in IoCHub | Cause | Fix |
|---|---|---|
| "CAPE is enabled but not set up…" | `url` unreachable from the Rocky box and `spawn` empty | confirm `curl $U/apiv2/` from Rocky; open the network path; check `cape-web` is running |
| "CAPE: … HTTP 429" | API rate limit | `ratelimit = no` in api.conf, restart cape-web |
| "CAPE: … HTTP 401/403" | token/auth | `token_auth_enabled = yes`, set the right `token` in cape.conf, regenerate with `drf_create_token` |
| status polling never completes | `[taskstatus]` disabled, or the guest never reverts/runs | enable the endpoint; verify the Windows snapshot name + agent in `kvm.conf`/`cuckoo.conf` |
| report has no IoCs | analysis ran but no network/dropped activity, or report format | confirm the sample actually did something; IoCHub reads the `json` report's `network`/`dropped`/`CAPE.payloads` |
| guest doesn't boot / no nesting | nested virt off (topology B) | enable `kvm_intel/kvm_amd nested=1` on the Rocky host; CPU `host-passthrough` on the Ubuntu VM |

---

## 9. Hand-off brief for Claude Code (run it on the CAPE host)

Paste something like this to Claude Code on the **Ubuntu** CAPE host. It can do
the scripted parts; it will have to stop and hand back for the licensed-Windows
GUI steps.

> You're on an Ubuntu 22.04 host that will run CAPEv2 (malware sandbox). Goal:
> install CAPEv2 and configure its REST API so an external IoCHub backend can
> drive it. Constraints: keep everything on the private network — never expose
> port 8000 to the internet. Steps:
> 1. Verify hardware virtualization (`egrep -c '(vmx|svm)' /proc/cpuinfo`) and,
>    if this host is itself a VM, confirm nested virt is available; report back
>    if it isn't before proceeding.
> 2. Clone `https://github.com/kevoreilly/CAPEv2`, read `installer/`'s current
>    README, set the installer vars (NETWORK_IFACE=virbr0, IFACE_IP=192.168.122.1,
>    a postgres PASSWD, USER=cape), then run `kvm-qemu.sh all` and `cape2.sh base`,
>    rebooting when the scripts say to. Surface any script errors instead of
>    plowing through them.
> 3. Enable+start `cape cape-processor cape-rooter cape-web`; confirm the REST
>    API answers on 127.0.0.1:8000.
> 4. Edit `/opt/CAPEv2/conf/api.conf`: `token_auth_enabled = yes`,
>    `ratelimit = no`, and enable the `tasksearch`, `taskcreate`, `taskstatus`,
>    `taskreport` endpoints. Restart `cape-web`.
> 5. Create a superuser and run `drf_create_token <user>`; print the token so I
>    can put it in IoCHub's cape.conf.
> 6. STOP before the Windows guest — I'll build and snapshot it by hand
>    (licensed ISO + virt-manager), then register it in `kvm.conf`/`cuckoo.conf`.
> 7. Give me the exact `curl` commands (with the token) to verify
>    `/apiv2/tasks/list/` and `/apiv2/tasks/search/sha256/<hash>/` from a
>    different host.
>
> Do not weaken firewall rules beyond what's needed for the libvirt guest
> network, and do not start submitting real malware until I've confirmed the
> guest snapshot works.
