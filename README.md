# adcontrol

**Active Directory object-control / permission analyzer.**

For any principal (user, group, or computer), `adcontrol` maps two things and
keeps them strictly separate:

- **Outbound** — every object the principal can control across the domain
  (GenericAll, WriteDacl, WriteOwner, DCSync, ForceChangePassword, AddMember,
  write-SPN, RBCD, shadow-creds, …), rolled up transitively through its group
  memberships.
- **Inbound** — every principal that can control the chosen object.

It is BloodHound-flavored but focused: it answers *"what can this account touch, and
who can touch this account"* as a readable report, not a graph you have to query.

Analysis is driven from AD object security descriptors (`nTSecurityDescriptor`)
collected over LDAP, plus — optionally — GPO-delivered rights and live per-host
RDP/local-admin membership. It can also run **fully offline** by importing an
existing BloodHound / SharpHound collection (`--bloodhound file.zip`), giving the
same outbound/inbound analysis, reports, and modal detail with no domain contact.

---

## Two separate scripts

adcontrol is split into two independent tools that never run in the same
process:

- **`adcontrol_scan.py`** — the gatherer. Does ALL enumeration/collection
  (live LDAP + ADCS + GPO + tier-3 host-rights/sessions, or an offline
  BloodHound import) and nothing else. No web server, no analysis beyond raw
  counts. Shows a live terminal dashboard (`rich`) with progress and stats
  while it runs, then writes the result to its own directory:
  `loot/<run_id>/` (`store.pkl` + `meta.json` + `scan.log`), one directory
  per run.
- **`adcontrol_web.py`** — the viewer/reporter. Run *after* a scan finishes.
  Never touches a domain or gathers anything itself — it only loads a
  `loot/<run_id>/` directory (picked in the browser, or via `--run`/`--latest`)
  and serves the outbound/inbound analysis, canned queries, attack-path
  chaining, and scoped/domain-wide report export against it.

This mirrors the split used in this user's other scan tools (e.g. ShareHunter):
gathering and viewing are separate concerns, so a scan can run unattended
(over SSH, in the background, on a jump box) while the viewer is opened
later, possibly on a different machine, purely against the loot it produced.

---

## Features

- **Outbound + inbound control**, always presented as two separate panels/sections.
- **Transitive group membership** — a right granted to a group the user nests
  into is correctly attributed to the user, with the group path shown.
- **DCSync detection** — synthesizes a single `DCSync` finding when a principal
  holds both `DS-Replication-Get-Changes` and `-Get-Changes-All` on the domain head.
- **ADCS (Certificate Services) analysis** — detects the classic ESC1–ESC4
  template misconfigurations (enrollee-suppliable SAN, Any-Purpose EKU,
  enrollment-agent templates, writable template objects), folded into the
  same outbound/inbound control model.
- **Attack-path chaining** — "how does principal A reach Domain Admin?"
  Chains one-hop control edges into full multi-hop paths, with a fast
  shortest-path mode and a fuller (slower) exhaustive-enumeration mode.
- **Canned queries panel** — pre-built domain-wide investigative queries
  (e.g. "which non-admin users can control something") without clicking
  through every principal by hand.
- **Domain-wide static report** (`adcontrol_web.py --offline-report`) — a
  single self-contained HTML file combining the canned queries, shortest
  paths to Tier-0, and every principal's outbound/inbound control, for
  domains too large to comfortably browse in the live GUI.
- **Live logon-session collection** (tier 3, opt-in) — enumerates who's
  logged on to member hosts via NetWkstaUserEnum/NetSessionEnum, feeding
  `HasSession` edges into attack-path chaining on a live pull (BloodHound's
  session-collection loop, for live collection).
- **Broad-trustee flagging** — control granted to Everyone / Authenticated Users /
  Domain Users is highlighted (it effectively means *every* user has it).
- **Three collection tiers** with explicit blast-radius control (see below).
- **Web GUI** (Flask) for browsing a loaded run: principal search, and
  per-principal report export.
- **Scoped reports** — export a self-contained HTML or Markdown report for any
  single principal, from the GUI or `adcontrol_web.py --subject`.
- **Auth**: password, pass-the-hash (NT hash), or Kerberos (with automatic TGT);
  plain LDAP with automatic fallback to LDAPS.
- **Offline-ready internals** — all analysis reads a normalized object store, so
  a live pull and a BloodHound/SharpHound import (`--bloodhound`) work through
  the exact same analysis engine and the exact same viewer.

---

## Collection tiers (blast-radius control)

You choose exactly how far `adcontrol_scan.py` reaches. **By default nothing
touches a member host** — only the DC is contacted.

| Tier | What it reads | Touches | Default |
|------|---------------|---------|---------|
| **1 — AD object ACLs** | `nTSecurityDescriptor` on all objects, via LDAP | DC only | always |
| **2 — GPO rights** | GPOs on the DC's `SYSVOL` share (Allow log on through RDP, Restricted Groups, GPP local admin) | **DC only** | **on** (`--no-gpo` to skip) |
| **3 — per-host RDP/admin** | Local `Administrators` / `Remote Desktop Users` membership (SAMR) + `SeRemoteInteractiveLogonRight` (LSA) | **every target host** | **off** |
| **3 — CA registry config** | Each CA's own `EditFlags`/`InterfaceFlags`/`DisableExtensionList`/security descriptor (Remote Registry Protocol) + an HTTP probe of `/certsrv/` | **every collected CA host** | **off** |

Tier 2 reads GPO-delivered rights without ever leaving the DC, because GPOs live
in `SYSVOL`. Only **tier 3** fans out to member hosts, and it does nothing unless
you explicitly ask for it with `--host-rights` (all collected computers) or
`--hosts <list>` (only the hosts you name).

Tier 3 also covers live logon-session collection — `--sessions` (all collected
computers) or `--session-hosts <list>` — which enumerates who's logged on to
each host via NetWkstaUserEnum/NetSessionEnum and feeds `HasSession` edges into
attack-path chaining, the same way BloodHound's session loop does.

Tier 3 also covers CA registry config — `--adcs-ca-config` — the only way to
see ESC6/ESC7/ESC11/ESC16 (none of those four are LDAP attributes; they live in
the CA server's own registry, not the DC's). Also probes each CA's Web
Enrollment endpoint over plain HTTP for the ESC8 exposure indicator (a GET
request only — not the NTLM relay attack itself).

GPO/host findings are kept in their own section and never mixed into the
AD-object control graph.

---

## Install

Requires Python 3.10+.

```bash
git clone <your-repo-url> adcontrol
cd adcontrol
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Or install it as a package (adds `adcontrol-scan` and `adcontrol-web` commands):

```bash
pip install .
```

`adcontrol_scan.py` needs `impacket`, `ldap3`, `rich`. `adcontrol_web.py` needs
`flask` (plus the shared `adcontrol/` package, which pulls in `impacket`/`ldap3`
for their SD/rights-name helpers even though it never opens a network connection).

---

## Usage

### 1. Scan (gather)

```bash
python3 adcontrol_scan.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local
```

Runs tier 1 (AD object ACLs) + ADCS + tier 2 (GPO, DC-only) by default, shows a
live terminal dashboard, and writes `loot/<run_id>/` when done.

Kerberos / pass-the-hash:

```bash
python3 adcontrol_scan.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local -k
python3 adcontrol_scan.py --dc dc01.corp.local -u user \
    --nthash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d corp.local
```

Add tier 3 (touches hosts — opt-in):

```bash
# Named hosts only (safest)
python3 adcontrol_scan.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local \
    --hosts ws01.corp.local,srv02.corp.local --session-hosts ws01.corp.local,srv02.corp.local

# Every enabled computer found in the domain (noisy — fans out to all hosts)
python3 adcontrol_scan.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local \
    --host-rights --sessions --adcs-ca-config
```

Skip the GPO plane (pure LDAP, zero SMB):

```bash
python3 adcontrol_scan.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local --no-gpo
```

Offline: import a BloodHound/SharpHound collection instead of scanning live
(still writes a `loot/<run_id>/` run, so the viewer works the same way):

```bash
python3 adcontrol_scan.py --bloodhound collection.zip
```

### 2. View / report (run after)

```bash
# Pick a run interactively from the browser
python3 adcontrol_web.py

# Load a specific run on startup
python3 adcontrol_web.py --run 20260811_120000

# Load the most recently finished run on startup
python3 adcontrol_web.py --latest
# open http://127.0.0.1:5006
```

No-GUI report generation straight from a loot run:

```bash
# Scoped report for one principal
python3 adcontrol_web.py --latest --subject alice --report alice.html

# Strictly offline: one self-contained whole-domain HTML report (canned
# queries + shortest paths to Tier-0 + every principal's control) — for
# domains too large to browse comfortably in the live GUI
python3 adcontrol_web.py --latest --offline-report
```

### Key options

**`adcontrol_scan.py`**

```
--bloodhound PATH    Offline: import a BloodHound zip/json/directory instead of scanning live
--dc HOST            Domain controller host/IP
-u, --username
-p, --password
-d, --domain         FQDN or NETBIOS
--nthash HASH        Pass-the-hash (LM:NT / :NT / NT)
-k, --kerberos       Use Kerberos
--aes-key HEX        AES key (implies Kerberos)
--dc-ip IP           Pin a DC IP for Kerberos/LDAP
--ldaps              Force LDAPS (default: try LDAP, fall back to LDAPS)
--no-gpo             Skip tier 2 (GPO plane)
--host-rights        Tier 3 against ALL collected computers
--hosts SPEC         Tier 3 against a file / single host / comma-separated list
--sessions           Tier 3: live logon-session enumeration against ALL collected computers
--session-hosts SPEC Tier 3: live logon-session enumeration against a file / single host / comma-separated list
--adcs-ca-config      Tier 3: read each CA's registry config (ESC6/7/11/16) + probe /certsrv/ over HTTP (ESC8)
--loot-dir PATH      Base directory for run output (default: ./loot)
```

**`adcontrol_web.py`**

```
--run RUN_ID          Load a specific loot run
--latest              Load the most recently finished loot run
--host                GUI bind host (default 127.0.0.1)
--port                GUI port (default 5006)
--subject NAME        No-GUI: print + optionally --report a scoped analysis, then exit
--report PATH         With --subject: write a scoped report (.html or .md)
--offline-report PATH No-GUI: write one whole-domain HTML report, then exit (path optional)
```

---

## Project layout

```
adcontrol_scan.py       Gathers — live collection or --bloodhound import; writes loot/<run_id>/
adcontrol_web.py        Views/reports — loads a loot/<run_id>/ run; web GUI or no-GUI report export
pyproject.toml          Packaging / console-script entry points
requirements.txt
adcontrol/
  loot.py               loot/<run_id>/ run storage (meta.json + store.pkl), shared by both scripts
  connection.py         LDAP auth (Kerberos / NTLM / LDAPS) + paged search + SD control
  collector.py          Pulls objects + security descriptors into the object store
  sddl.py               nTSecurityDescriptor parser → named rights
  rights.py             Access-mask + extended-right/GUID → right-name maps, well-known SIDs
  model.py              Normalized object store (the seam for offline dumps)
  bloodhound.py         Offline import of a BloodHound/SharpHound zip/json/directory
  graph.py              Transitive group-membership resolution
  analyze.py            Outbound + inbound control edges (kept separate) + DCSync synthesis
  adcs.py               ADCS template/CA analysis — every LDAP-derivable ESC (1-5,9,13-15,17) + CA-registry ESCs (6-8,11,16)
  adcs_ca.py            Tier 3 — CA registry config (EditFlags/InterfaceFlags/DisableExtensionList/security) via RRP + HTTP probe
  paths.py              Multi-hop attack-path chaining over the control graph (shortest / full)
  queries.py            Canned domain-wide queries for the GUI's Queries panel
  gpo.py                Tier 2 — GPO rights from the DC's SYSVOL
  hostrights.py          Tier 3 — per-host RDP/admin via SAMR + LSA
  sessions.py            Tier 3 — live logon-session collection via SAMR/wkssvc/srvsvc
  smbauth.py             Shared SMB/DCE-RPC credential helper for tiers 2 & 3
  report.py              Scoped HTML / Markdown report export (single principal)
  report_domain.py       Domain-wide static HTML report (adcontrol_web.py --offline-report)
  app.py                 Flask read-only web server + REST API (no collection code)
  templates/index.html   Single-page web GUI
```

Each scan/import gets `loot/<run_id>/` (`store.pkl` + `meta.json` + `scan.log`,
git-ignored) so `adcontrol_web.py` can load it later without re-querying the
domain.

---

## Notes & limitations

- Loot directories are Python pickles (`store.pkl`) — do not load a run you did
  not generate yourself.
- Tier 3 (SAMR/LSA) has been validated against the impacket API surface but
  should be exercised in a lab before you rely on it in an engagement.

## Authorization

For use only against Active Directory environments you own or are explicitly
authorized to assess.
