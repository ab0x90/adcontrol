"""
Canned domain-wide queries for the GUI's Queries panel.

Each query scans the whole ObjectStore (via the Analyzer) and returns a flat
list of principal/object hits, so the GUI can answer investigative questions
like "which non-admin users can control something?" without the operator
clicking through every principal by hand.

A query returns a list of dicts shaped like a principals-list row:
    {key, label, class, object_class, dn, enabled, admin_count, note}
`note` is a short per-hit explanation (e.g. the right(s) that matched), shown
in the results list. Clicking a hit selects that principal in the normal
detail view.

Everything here reads only from the Analyzer/ObjectStore — no LDAP.
"""
from __future__ import annotations

from adcontrol.model import ObjectStore, RawObject
from adcontrol.analyze import Analyzer
from adcontrol import rights

# Object classes that are real selectable security principals.
_PRINCIPAL_CLASSES = ("user", "group", "computer")


def _friendly(object_class: str) -> str:
    return {
        "user": "user", "group": "group", "computer": "computer",
        "groupPolicyContainer": "gpo", "organizationalUnit": "ou",
        "domain": "domain", "container": "container",
    }.get(object_class, "other")


def _is_admin(az: Analyzer, obj: RawObject) -> bool:
    """
    A principal is treated as 'admin' if it carries adminCount, or any SID in
    its effective set is a built-in high-privilege admin trustee (Domain/
    Enterprise/Schema Admins, BUILTIN\\Administrators, operator groups, …).
    Groups that ARE those admin groups also count.
    """
    if obj.admin_count:
        return True
    if rights.is_builtin_admin_trustee(obj.sid or ""):
        return True
    for sid in az.graph.effective_sids(obj):
        if rights.is_builtin_admin_trustee(sid):
            return True
    return False


def _row(obj: RawObject, note: str = "") -> dict:
    return {
        "key": obj.sid or obj.dn,
        "label": obj.label,
        "class": _friendly(obj.object_class),
        "object_class": obj.object_class,
        "dn": obj.dn,
        "enabled": obj.enabled,
        "admin_count": obj.admin_count,
        "note": note,
    }


# Cap expanded members per group so a huge group (Domain Users) can't bloat a
# response; the count still reflects the true total.
_MAX_MEMBERS = 200


def _expand_members(row: dict, store: ObjectStore, az: Analyzer) -> None:
    """
    For a group hit, attach its transitive members so the operator can see who
    actually inherits the group's finding. Mutates `row` in place, adding:
        member_count : true transitive member count
        members      : up to _MAX_MEMBERS resolved {key,label,class,enabled}
                       (users/computers/nested groups), sorted class then label
    Non-group rows are left unchanged.
    """
    if row["object_class"] != "group":
        return
    grp = store.by_sid(row["key"]) or store.by_dn(row["dn"])
    if grp is None:
        return
    sids = az.graph.member_sids_of(grp)
    row["member_count"] = len(sids)
    members = []
    for sid in sids:
        m = store.by_sid(sid)
        if m is None:
            members.append({"key": sid, "label": az.graph.label_for_sid(sid),
                            "class": "other", "enabled": True})
        else:
            members.append({"key": m.sid or m.dn, "label": m.label,
                            "class": _friendly(m.object_class), "enabled": m.enabled})
    members.sort(key=lambda x: (x["class"], x["label"].lower()))
    row["members"] = members[:_MAX_MEMBERS]
    row["members_truncated"] = len(members) > _MAX_MEMBERS


# ---------------------------------------------------------------------------
# Individual query implementations
# ---------------------------------------------------------------------------
def _principals(store: ObjectStore):
    return [o for o in store.objects.values() if o.object_class in _PRINCIPAL_CLASSES]


def q_nonadmin_users_outbound(store, az):
    """Non-admin USERS that can control at least one object."""
    out = []
    for o in _principals(store):
        if o.object_class != "user" or _is_admin(az, o):
            continue
        edges = [e for e in az.outbound(o) if not e.builtin_noise]
        if edges:
            highs = sum(1 for e in edges if e.severity == "high")
            note = f"{len(edges)} outbound" + (f" · {highs} high" if highs else "")
            out.append(_row(o, note))
    return out


def q_nonadmin_high_outbound(store, az):
    """Any non-admin principal holding at least one HIGH-severity outbound edge."""
    out = []
    for o in _principals(store):
        if _is_admin(az, o):
            continue
        highs = [e for e in az.outbound(o) if e.severity == "high" and not e.builtin_noise]
        if highs:
            sample = ", ".join(sorted({e.right for e in highs})[:3])
            out.append(_row(o, f"{len(highs)} high · {sample}"))
    return out


def q_dcsync(store, az):
    """
    Principals that can DCSync the domain. The analyzer synthesizes this as a
    'DCSync (replicate secrets)' edge when a principal effectively holds both
    DS-Replication-Get-Changes and -All on the domain head, so we match the
    DCSync-prefixed right rather than an exact string.
    """
    out = []
    for o in _principals(store):
        if any(e.right.startswith("DCSync") for e in az.outbound(o)):
            out.append(_row(o, "holds DCSync (replicate secrets)"))
    return out


def q_controls_admins(store, az):
    """Principals with control over an admin / adminCount-protected object."""
    out = []
    for o in _principals(store):
        hits = []
        for e in az.outbound(o):
            if e.builtin_noise:
                continue
            tgt = store.by_dn(e.target_dn)
            if tgt and (tgt.admin_count or rights.is_builtin_admin_trustee(tgt.sid or "")):
                hits.append(e)
        if hits:
            targets = ", ".join(sorted({e.target_label for e in hits})[:3])
            out.append(_row(o, f"controls protected: {targets}"))
    return out


def q_broad_controlled(store, az):
    """Objects controllable by a broad trustee (Everyone / Auth Users / Domain
    Users) — i.e. effectively controllable by *every* user."""
    out = []
    for o in store.objects.values():
        if any(e.broad and not e.builtin_noise for e in az.inbound(o)):
            rights_hit = ", ".join(sorted({e.right for e in az.inbound(o) if e.broad})[:3])
            out.append(_row(o, f"broad inbound: {rights_hit}"))
    return out


def q_kerberoastable(store, az):
    """Enabled users with a Service Principal Name (kerberoastable)."""
    out = []
    for o in _principals(store):
        if o.object_class != "user":
            continue
        spns = o.extra.get("spn") or []
        if spns and o.enabled:
            out.append(_row(o, f"SPN: {spns[0]}" + (f" (+{len(spns)-1})" if len(spns) > 1 else "")))
    return out


# Broad control rights that ENCOMPASS the takeover primitives: holding any of
# these over a user/computer lets you write msDS-KeyCredentialLink (shadow creds),
# msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD), or the SPN — so they are
# takeover paths too, just less obvious than a scoped write.
_BROAD_TAKEOVER_RIGHTS = (
    "genericall", "genericwrite", "writedacl", "writeowner",
    "allextendedrights", "writeallproperties", "owns",
)


def _takeover_kind(right: str, target_class: str) -> str | None:
    """How *right* enables taking over a target of *target_class*, or None if it
    doesn't. Returns:
      "direct" — a specific takeover primitive (shadow creds / RBCD / write-SPN);
      "broad"  — a full-control right (GenericAll/Write, WriteDacl/Owner,
                 AllExtendedRights…) over a user/computer, which encompasses the
                 primitives above.
    Broad rights only count over users/computers (where the shadow-cred/RBCD/SPN
    attributes live); over a group they mean group-membership control, handled by
    the other queries, not object takeover."""
    r = right.lower()
    if ("keycredentiallink" in r          # shadow credentials
            or "allowedtoactonbehalf" in r  # RBCD
            or "service-principal-name" in r or r.endswith(":spn") or "writespn" in r):
        return "direct"
    if target_class in ("user", "computer") and any(r.startswith(b) for b in _BROAD_TAKEOVER_RIGHTS):
        return "broad"
    return None


def _is_takeover_right(right: str) -> bool:
    """Back-compat: True if the right is a *direct* takeover primitive (target
    class agnostic). Retained for any external callers; the query itself now uses
    _takeover_kind so it can also credit broad rights over users/computers."""
    return _takeover_kind(right, "computer") == "direct"


def q_takeover_inbound(store, az):
    """Objects a principal can take over, grouped BY THE ACTOR. A takeover path is
    either a *direct* primitive (shadow creds / RBCD / write-SPN) or a *broad*
    full-control right (GenericAll/Write, WriteDacl/Owner, AllExtendedRights) over
    a user/computer — the broad right encompasses the primitives, so it is a
    takeover path too. Each target records which rights and whether it's a direct
    or broad path so the report can distinguish them.

    Row shape (distinct from plain principal rows): the actor's normal principal
    fields, plus:
        takeover_count : number of objects the actor can take over
        takeovers      : [{target, target_class, right, kind}] sorted by target
    """
    # actor_sid -> {"targets": {target_dn: {label,class,rights,kind}}}
    by_actor: dict[str, dict] = {}
    for o in _principals(store):
        for e in az.inbound(o):
            if e.builtin_noise:
                continue
            kind = _takeover_kind(e.right, o.object_class)
            if kind is None:
                continue
            actor = by_actor.setdefault(e.source_sid, {"label": e.source_label, "targets": {}})
            tgt = actor["targets"].setdefault(
                o.dn, {"label": o.label, "class": _friendly(o.object_class),
                       "rights": set(), "kind": "broad"})
            tgt["rights"].add(e.right)
            # A direct primitive is the stronger classification for the target.
            if kind == "direct":
                tgt["kind"] = "direct"

    out = []
    for actor_sid, info in by_actor.items():
        actor_obj = store.by_sid(actor_sid)
        # Build the row around the actor principal (falls back to a synthetic
        # label row when the trustee isn't a resolvable store object).
        if actor_obj is not None:
            row = _row(actor_obj)
        else:
            row = {"key": actor_sid, "label": info["label"], "class": "other",
                   "object_class": "", "dn": "", "enabled": True, "admin_count": 0,
                   "note": ""}
        takeovers = [
            {"target": t["label"], "target_class": t["class"],
             "right": ", ".join(sorted(t["rights"])), "kind": t["kind"]}
            for t in info["targets"].values()]
        takeovers.sort(key=lambda x: (x["kind"] != "direct", x["target"].lower()))
        row["takeover_count"] = len(takeovers)
        row["takeovers"] = takeovers
        # Mark expected built-in privileged groups (Key Admins, operators, admins)
        # so the report can hide them by default — their takeover rights are by
        # design, not a finding.
        row["expected"] = rights.is_wellknown_privileged_group(actor_sid)
        row["note"] = f"can take over {len(takeovers)} object(s)"
        out.append(row)
    # Most impactful (most objects) first.
    out.sort(key=lambda r: (-r["takeover_count"], r["label"].lower()))
    return out


# Rights that let a trustee modify a GPO's settings/policy (and thus push code to
# everything the GPO is linked to). Editing a GPO needs write access to it.
_GPO_CONTROL_RIGHTS = (
    "genericall", "genericwrite", "writedacl", "writeowner", "owns",
    "writeproperty:gpcfilesyspath",   # write the GPO's file path (edit settings)
    "writeallproperties",
)


def _is_gpo_control_right(right: str) -> bool:
    r = right.lower()
    return any(r.startswith(g) for g in _GPO_CONTROL_RIGHTS)


def q_gpo_control(store, az):
    """Principals that can control a Group Policy Object — i.e. edit its settings
    and push code (scheduled/immediate tasks, scripts, local-admin membership) to
    every computer/user the GPO applies to. Grouped BY THE ACTOR, like the
    takeover query. Built-in privileged groups are tagged ``expected`` (hidden by
    default in the report).

    Row shape adds:
        gpo_count : number of GPOs the actor can control
        gpos      : [{target, right}] sorted by GPO name
    """
    gpo_objs = [o for o in store.objects.values()
                if o.object_class in ("groupPolicyContainer", "gpo")]
    by_actor: dict[str, dict] = {}
    for g in gpo_objs:
        for e in az.inbound(g):
            if e.builtin_noise or not _is_gpo_control_right(e.right):
                continue
            actor = by_actor.setdefault(e.source_sid, {"label": e.source_label, "gpos": {}})
            tgt = actor["gpos"].setdefault(g.dn, {"label": g.label, "rights": set()})
            tgt["rights"].add(e.right)

    out = []
    for actor_sid, info in by_actor.items():
        actor_obj = store.by_sid(actor_sid)
        if actor_obj is not None:
            row = _row(actor_obj)
        else:
            row = {"key": actor_sid, "label": info["label"], "class": "other",
                   "object_class": "", "dn": "", "enabled": True, "admin_count": 0,
                   "note": ""}
        gpos = [{"target": t["label"], "target_class": "gpo",
                 "right": ", ".join(sorted(t["rights"]))}
                for t in info["gpos"].values()]
        gpos.sort(key=lambda x: x["target"].lower())
        row["gpo_count"] = len(gpos)
        row["gpos"] = gpos
        row["expected"] = rights.is_wellknown_privileged_group(actor_sid)
        row["note"] = f"can control {len(gpos)} GPO(s)"
        out.append(row)
    out.sort(key=lambda r: (-r["gpo_count"], r["label"].lower()))
    return out


def q_enabled_admincount(store, az):
    """Enabled principals flagged with adminCount=1 (protected/admin lineage)."""
    out = []
    for o in _principals(store):
        if o.admin_count and o.enabled:
            out.append(_row(o, "adminCount=1, enabled"))
    return out


def q_adcs_esc(store, az):
    """ADCS certificate-template misconfigurations (ESC1–ESC4), one row per
    finding. Row carries the template as the 'principal' and the enrollers/ESC in
    the note; extra fields (esc, template, enrollers, reasons) let the report
    render richer detail. Ordered by ESC id."""
    from adcontrol import adcs as adcs_mod
    findings = getattr(store, "adcs_findings", None)
    if not findings:
        adcs_mod.analyze_adcs(store, az)
        findings = store.adcs_findings
    out = []
    for f in findings:
        actors = ", ".join(f.enrollers[:6]) + ("…" if len(f.enrollers) > 6 else "")
        out.append({
            "key": f.template_dn or f.template, "label": f.template,
            "class": "gpo" if False else "adcs", "object_class": "",
            "dn": f.template_dn, "enabled": True, "admin_count": 0,
            "note": f"{f.esc} — abusable by: {actors}",
            "esc": f.esc, "template": f.template, "severity": f.severity,
            "detail": f.detail, "reasons": f.reasons,
            "enrollers": f.enrollers, "enroller_sids": f.enroller_sids,
        })
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# id → (label, description, fn). Order is display order.
QUERY_REGISTRY = {
    "nonadmin_users_outbound": (
        "Non-admin users with outbound control",
        "Users that are not admins yet can control at least one object.",
        q_nonadmin_users_outbound),
    "nonadmin_high_outbound": (
        "Non-admin principals with HIGH control",
        "Non-admin users/groups/computers holding a high-severity control right.",
        q_nonadmin_high_outbound),
    "dcsync": (
        "DCSync-capable principals",
        "Principals that can replicate secrets from the domain (DCSync).",
        q_dcsync),
    "controls_admins": (
        "Principals controlling admin objects",
        "Non-obvious control over admin / adminCount-protected objects.",
        q_controls_admins),
    "broad_controlled": (
        "Objects controllable by Everyone/Auth Users",
        "Objects whose ACL grants control to a broad trustee (any user).",
        q_broad_controlled),
    "kerberoastable": (
        "Kerberoastable users (SPN set)",
        "Enabled user accounts with a Service Principal Name.",
        q_kerberoastable),
    "takeover_inbound": (
        "Objects takeover-able (by actor)",
        "Principals that can take over a user/computer — via a direct primitive "
        "(shadow creds / RBCD / write-SPN) or a broad full-control right that "
        "encompasses one. Grouped by the actor.",
        q_takeover_inbound),
    "gpo_control": (
        "GPO control (by actor)",
        "Principals that can edit a Group Policy Object and push code to every "
        "computer/user it's linked to. Grouped by the actor.",
        q_gpo_control),
    "enabled_admincount": (
        "Enabled adminCount principals",
        "Enabled principals in the admin protected set (adminCount=1).",
        q_enabled_admincount),
    "adcs_esc": (
        "ADCS ESC misconfigurations",
        "Vulnerable certificate templates (ESC1–ESC4) — enrollee-supplies-subject, "
        "any-purpose/enrollment-agent EKUs, or writable template objects.",
        q_adcs_esc),
}


def list_queries() -> list[dict]:
    return [{"id": k, "label": v[0], "description": v[1]}
            for k, v in QUERY_REGISTRY.items()]


def run_query(query_id: str, store: ObjectStore, az: Analyzer) -> list[dict]:
    entry = QUERY_REGISTRY.get(query_id)
    if not entry:
        raise KeyError(query_id)
    hits = entry[2](store, az)
    # Attach group membership so group hits show who inherits the finding.
    for row in hits:
        _expand_members(row, store, az)
    # Ordering: actor-grouped rows (takeover_count) lead by impact — most objects
    # first; everything else by class then label.
    if any("takeover_count" in r for r in hits):
        hits.sort(key=lambda r: (-r.get("takeover_count", 0), r["label"].lower()))
    else:
        hits.sort(key=lambda r: (r["class"], r["label"].lower()))
    return hits
