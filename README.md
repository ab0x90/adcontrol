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

## Features

- **Outbound + inbound control**, always presented as two separate panels/sections.
- **Transitive group membership** — a right granted to a group the user nests
  into is correctly attributed to the user, with the group path shown.
- **DCSync detection** — synthesizes a single `DCSync` finding when a principal
  holds both `DS-Replication-Get-Changes` and `-Get-Changes-All` on the domain head.
- **Broad-trustee flagging** — control granted to Everyone / Authenticated Users /
  Domain Users is highlighted (it effectively means *every* user has it).
- **Three collection tiers** with explicit blast-radius control (see below).
- **Web GUI** (Flask + SocketIO) with live collection progress, principal search,
  and per-principal report export.
- **Scoped reports** — export a self-contained HTML or Markdown report for any
  single principal.
- **Auth**: password, pass-the-hash (NT hash), or Kerberos (with automatic TGT);
  plain LDAP with automatic fallback to LDAPS.
- **Offline-ready internals** — all analysis reads a normalized object store, so
  an offline-dump parser can be added without touching the analysis engine.

---

## Collection tiers (blast-radius control)

You choose exactly how far collection reaches. **By default nothing touches a
member host** — only the DC is contacted.

| Tier | What it reads | Touches | Default |
|------|---------------|---------|---------|
| **1 — AD object ACLs** | `nTSecurityDescriptor` on all objects, via LDAP | DC only | always |
| **2 — GPO rights** | GPOs on the DC's `SYSVOL` share (Allow log on through RDP, Restricted Groups, GPP local admin) | **DC only** | **on** (`--no-gpo` to skip) |
| **3 — per-host RDP/admin** | Local `Administrators` / `Remote Desktop Users` membership (SAMR) + `SeRemoteInteractiveLogonRight` (LSA) | **every target host** | **off** |

Tier 2 reads GPO-delivered rights without ever leaving the DC, because GPOs live
in `SYSVOL`. Only **tier 3** fans out to member hosts, and it does nothing unless
you explicitly ask for it with `--host-rights` (all collected computers) or
`--hosts <list>` (only the hosts you name).

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

Or install it as a package (adds an `adcontrol` command):

```bash
pip install .
```

Dependencies: `impacket`, `ldap3`, `flask`, `flask-socketio`. The web GUI uses
SocketIO's threading mode, so no eventlet/gevent is required.

---

## Usage

Run from a clone (`python3 adcontrol.py …`), as a module (`python3 -m adcontrol …`),
or via the installed console script (`adcontrol …`). All three are equivalent.

### Web GUI (default)

```bash
python3 adcontrol.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local
# open http://127.0.0.1:5006
```

Fill in the DC and credentials in the browser, pick the collection tier, click
**Collect**, then search for a principal to see its outbound/inbound control and
export a report.

### CLI only (no web server)

```bash
python3 adcontrol.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local \
    --nogui --subject alice --report alice.html
```

### Kerberos / pass-the-hash

```bash
# Kerberos (obtains a TGT from the password automatically)
python3 adcontrol.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local -k

# Pass-the-hash
python3 adcontrol.py --dc dc01.corp.local -u user \
    --nthash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d corp.local
```

### Per-host RDP / local-admin (tier 3 — opt-in, touches hosts)

```bash
# Only the hosts you name (safest)
python3 adcontrol.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local \
    --hosts ws01.corp.local,srv02.corp.local

# Every enabled computer found in the domain (noisy — fans out to all hosts)
python3 adcontrol.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local \
    --host-rights
```

### Skip the GPO plane (pure LDAP, zero SMB)

```bash
python3 adcontrol.py --dc dc01.corp.local -u user -p 'Password1' -d corp.local --no-gpo
```

### Key options

```
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
--nogui              CLI only
--subject NAME       (CLI) principal to analyze
--report PATH        (CLI) write report (.html or .md)
--port N             GUI port (default 5006)
```

---

## Project layout

```
adcontrol.py            Convenience launcher (runs straight from a clone)
pyproject.toml          Packaging / console-script entry point
requirements.txt
adcontrol/
  cli.py                Argument parsing, CLI + GUI mode selection
  connection.py         LDAP auth (Kerberos / NTLM / LDAPS) + paged search + SD control
  collector.py          Pulls objects + security descriptors into the object store
  sddl.py               nTSecurityDescriptor parser → named rights
  rights.py             Access-mask + extended-right/GUID → right-name maps, well-known SIDs
  model.py              Normalized object store (the seam for future offline dumps)
  graph.py              Transitive group-membership resolution
  analyze.py            Outbound + inbound control edges (kept separate) + DCSync synthesis
  gpo.py                Tier 2 — GPO rights from the DC's SYSVOL
  hostrights.py         Tier 3 — per-host RDP/admin via SAMR + LSA
  smbauth.py            Shared SMB/DCE-RPC credential helper for tiers 2 & 3
  report.py             Scoped HTML / Markdown report export
  app.py                Flask + SocketIO web server + REST API
  templates/index.html  Single-page web GUI
```

Collected sessions are pickled to `adcontrol_sessions/` (git-ignored) so a
collection can be reloaded in the GUI without re-querying the domain.

---

## Notes & limitations

- The web GUI loads the Socket.IO client from a CDN; on a fully air-gapped host
  the live-progress stream won't load (the REST endpoints still work). Vendor the
  script locally if you need offline GUI use.
- Session files are Python pickles — do not load a session file you did not
  generate yourself.
- Tier 3 (SAMR/LSA) has been validated against the impacket API surface but
  should be exercised in a lab before you rely on it in an engagement.

## Authorization

For use only against Active Directory environments you own or are explicitly
authorized to assess.
