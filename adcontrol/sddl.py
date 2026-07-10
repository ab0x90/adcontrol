"""
Parse an ``nTSecurityDescriptor`` blob into a list of named-right ACEs.

Turns each ACE's access mask + object-type GUID into the human-meaningful
control right it represents (GenericAll, WriteDacl, DCSync, ForceChangePassword,
Self-Membership, write-SPN, RBCD, shadow-creds, ...).

Field access patterns were confirmed against impacket ldaptypes on a genuinely
parsed descriptor:
  sd['Dacl'].aces            -> list of parsed ACE
  ace['AceType']             -> 0/1 (allowed/denied), 5/6 (allowed/denied OBJECT)
  ace['AceFlags']            -> INHERITED_ACE = 0x10
  body = ace['Ace']
  body['Mask']['Mask']       -> int access mask
  body['Sid']                -> bytes -> LDAP_SID(...).formatCanonical()
  body['Flags'] & 0x1        -> object-type GUID present
  bin_to_string(body['ObjectType']).lower() -> dashed GUID
"""

from __future__ import annotations

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string

from adcontrol import rights
from adcontrol.model import Ace

INHERITED_ACE = 0x10
ACE_OBJECT_TYPE_PRESENT = 0x01

# ACE types we treat as *granting* (denied ACEs are recorded but flagged).
_ALLOWED_TYPES = {
    ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,          # 0x00
    ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,   # 0x05
}
_DENIED_TYPES = {
    ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE,           # 0x01
    ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE,    # 0x06
}
_OBJECT_TYPES = {
    ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
    ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE,
}

_M = rights.ACCESS_MASK


def _sid_str(raw) -> str:
    if isinstance(raw, (bytes, bytearray)):
        return ldaptypes.LDAP_SID(data=bytes(raw)).formatCanonical()
    try:
        return raw.formatCanonical()
    except Exception:
        return str(raw)


def _named_rights_for_ace(mask: int, objtype: str, schema_names: dict) -> list[tuple[str, str, str]]:
    """Return list of (right_name, severity, applies_to) for one ACE's mask+objtype.

    A single ACE can express several distinct capabilities depending on which
    mask bits are set and whether an object-type GUID scopes it. Full-control
    bits (GenericAll/WriteDacl/...) only count as "own the object" when they are
    NOT scoped to a single attribute/extended-right (i.e. no object-type GUID),
    matching AD semantics.
    """
    out: list[tuple[str, str, str]] = []
    has_objtype = bool(objtype)

    # --- object-scoped capabilities (control-access / write-prop / validated) --
    if has_objtype:
        # Extended right (control access) — DS_CONTROL_ACCESS bit + rightsGuid.
        # Resolve the name via the curated + impacket well-known tables, then the
        # live schema map, then the raw GUID as a last resort.
        if mask & _M["ADS_RIGHT_DS_CONTROL_ACCESS"]:
            er = rights.extended_right_name(objtype)
            if er:
                out.append((er[0], er[1], objtype))
            else:
                friendly = schema_names.get(objtype)
                out.append((f"ExtendedRight:{friendly or objtype}",
                            "medium" if friendly else "low", objtype))

        # Write a specific property / property-set.
        if mask & _M["ADS_RIGHT_DS_WRITE_PROP"]:
            wp = rights.WRITE_PROP_GUIDS.get(objtype)
            if wp:
                out.append((f"WriteProperty:{wp[0]}", wp[1], objtype))
            else:
                friendly = schema_names.get(objtype)
                out.append((f"WriteProperty:{friendly or objtype}", "low", objtype))

        # Read a specific property — flag only if it reads a secret (LAPS etc.).
        if mask & _M["ADS_RIGHT_DS_READ_PROP"]:
            friendly = (schema_names.get(objtype) or "").lower()
            if friendly in rights.LAPS_ATTR_NAMES:
                out.append((f"ReadLAPSPassword:{friendly}", "high", objtype))

        # Validated write (DS_SELF) — e.g. Self-Membership, validated SPN/DNS.
        if mask & _M["ADS_RIGHT_DS_SELF"]:
            vw = rights.VALIDATED_WRITES.get(objtype)
            if vw:
                out.append((vw[0], vw[1], objtype))
    else:
        # No object type -> these bits mean "the whole object / all of that class".
        if mask & _M["ADS_RIGHT_DS_CONTROL_ACCESS"]:
            r = rights.FULL_CONTROL_MASKS["AllExtendedRights"]
            out.append(("AllExtendedRights", r[1], ""))
        if mask & _M["ADS_RIGHT_DS_WRITE_PROP"]:
            out.append(("WriteAllProperties", "high", ""))
        if mask & _M["ADS_RIGHT_DS_SELF"]:
            out.append(("AllValidatedWrites", "medium", ""))

    # --- standard/generic full-control bits (never object-scoped) --------------
    for name, (bit, sev, _desc) in rights.FULL_CONTROL_MASKS.items():
        if name == "AllExtendedRights":
            continue  # handled above (depends on objtype presence)
        if mask & bit:
            out.append((name, sev, ""))

    # GENERIC_WRITE also implies write-prop + self across the object.
    if mask & _M["GENERIC_WRITE"] and not any(o[0] == "GenericWrite" for o in out):
        out.append(("GenericWrite", "high", ""))

    return out


def _resolve_guid_name(guid: str, schema_names: dict) -> str:
    """Best-effort friendly name for an object-type GUID used as a scope.

    Order: "" (whole object) stays "" · live schema map (attributes/property
    sets) · well-known extended-right names (impacket table) · raw GUID."""
    if not guid:
        return ""
    if guid in schema_names:
        return schema_names[guid]
    er = rights.extended_right_name(guid)
    if er:
        return er[0]
    return guid


def parse_descriptor(blob: bytes, schema_names: dict | None = None):
    """Parse an nTSecurityDescriptor.

    Returns ``(owner_sid, aces)`` where ``aces`` is a list of
    :class:`adcontrol.model.Ace`. Denied ACEs are included with a ``right``
    prefixed ``DENY:`` so the analyzer can account for them without treating them
    as grants.
    """
    schema_names = schema_names or {}
    if not blob:
        return "", []
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=bytes(blob))
    except Exception:
        return "", []

    owner = ""
    try:
        owner = _sid_str(sd["OwnerSid"].getData() if hasattr(sd["OwnerSid"], "getData") else sd["OwnerSid"])
    except Exception:
        owner = ""

    dacl = sd["Dacl"]
    aces: list[Ace] = []
    if not dacl or not getattr(dacl, "aces", None):
        return owner, aces

    for ace in dacl.aces:
        atype = ace["AceType"]
        if atype not in _ALLOWED_TYPES and atype not in _DENIED_TYPES:
            continue  # audit/label/callback ACEs — not relevant to grant analysis
        body = ace["Ace"]
        try:
            mask = int(body["Mask"]["Mask"])
        except Exception:
            continue
        trustee = _sid_str(body["Sid"])

        objtype = ""
        if atype in _OBJECT_TYPES:
            try:
                if int(body["Flags"]) & ACE_OBJECT_TYPE_PRESENT and body["ObjectType"]:
                    objtype = bin_to_string(body["ObjectType"]).lower()
            except Exception:
                objtype = ""

        inherited = bool(int(ace["AceFlags"]) & INHERITED_ACE)
        denied = atype in _DENIED_TYPES

        for right_name, sev, applies in _named_rights_for_ace(mask, objtype, schema_names):
            aces.append(Ace(
                trustee_sid=trustee,
                right=(f"DENY:{right_name}" if denied else right_name),
                severity=sev,
                applies_to=_resolve_guid_name(applies, schema_names),
                ace_flags=int(ace["AceFlags"]),
                inherited=inherited,
                raw_mask=mask,
            ))

    return owner, aces
