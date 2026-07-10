"""
Access-mask bits, extended-right / property-set / validated-write GUIDs, and
well-known SIDs — the reference data that turns a raw ACE into a named,
human-meaningful control right.

GUIDs are stored lowercase, dashed, no braces (the form impacket's
``bin_to_string`` produces after ``.lower()``).
"""

# ---------------------------------------------------------------------------
# ACCESS_MASK bits (from the AD access-rights model).
# Reference: MS-ADTS / winnt.h ACCESS_MASK layout.
# ---------------------------------------------------------------------------
ACCESS_MASK = {
    "GENERIC_READ":            0x80000000,
    "GENERIC_WRITE":           0x40000000,
    "GENERIC_EXECUTE":         0x20000000,
    "GENERIC_ALL":             0x10000000,
    "MAXIMUM_ALLOWED":         0x02000000,
    "ACCESS_SYSTEM_SECURITY":  0x01000000,
    "SYNCHRONIZE":             0x00100000,
    "WRITE_OWNER":             0x00080000,
    "WRITE_DACL":              0x00040000,
    "READ_CONTROL":            0x00020000,
    "DELETE":                  0x00010000,
    # AD-specific (control access) bits, low word:
    "ADS_RIGHT_DS_CONTROL_ACCESS":  0x00000100,  # extended right (needs objtype GUID)
    "ADS_RIGHT_DS_CREATE_CHILD":    0x00000001,
    "ADS_RIGHT_DS_DELETE_CHILD":    0x00000002,
    "ADS_RIGHT_ACTRL_DS_LIST":      0x00000004,
    "ADS_RIGHT_DS_SELF":            0x00000008,  # validated write (needs objtype GUID)
    "ADS_RIGHT_DS_READ_PROP":       0x00000010,
    "ADS_RIGHT_DS_WRITE_PROP":      0x00000020,  # write property (objtype GUID = attr/propset)
    "ADS_RIGHT_DS_DELETE_TREE":     0x00000040,
    "ADS_RIGHT_DS_LIST_OBJECT":     0x00000080,
}

# The masks that, on their own (no object-type GUID), grant dangerous control.
# name -> (mask bit, severity, description)
FULL_CONTROL_MASKS = {
    "GenericAll":  (ACCESS_MASK["GENERIC_ALL"],  "high",   "Full control over the object"),
    "GenericWrite":(ACCESS_MASK["GENERIC_WRITE"],"high",   "Write any (non-protected) attribute"),
    "WriteOwner":  (ACCESS_MASK["WRITE_OWNER"],  "high",   "Take ownership of the object"),
    "WriteDacl":   (ACCESS_MASK["WRITE_DACL"],   "high",   "Rewrite the object's DACL (grant self anything)"),
    "Delete":      (ACCESS_MASK["DELETE"],       "medium", "Delete the object"),
    "AllExtendedRights": (ACCESS_MASK["ADS_RIGHT_DS_CONTROL_ACCESS"], "high",
                          "All control-access rights (only when no object-type GUID present)"),
}

# ---------------------------------------------------------------------------
# Extended-right GUIDs (rightsGuid, granted via CONTROL_ACCESS bit + objtype).
# ---------------------------------------------------------------------------
# Attack-relevant control-access rights, with a severity we assign. This is the
# CURATED subset — only rights where the severity is meaningful for analysis.
# For *naming* every other well-known right, we defer to impacket's authoritative
# msada_guids.EXTENDED_RIGHTS table (80 entries, correct GUIDs, ships with the
# dependency) via extended_right_name() below — so we never hand-maintain (and
# risk mistyping) the full list.
EXTENDED_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes",           "high"),
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes-All",       "high"),
    "89e95b76-444d-4c62-991a-0facbeda640c": ("DS-Replication-Get-Changes-In-Filtered-Set", "medium"),
    "00299570-246d-11d0-a768-00aa006e0529": ("User-Force-Change-Password",           "high"),
    "ab721a53-1e2f-11d0-9819-00aa0040529b": ("User-Change-Password",                 "low"),
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": ("Reanimate-Tombstones",                 "medium"),
    "ba33815a-4f93-4c76-87f3-57574bff8109": ("Migrate-SID-History",                  "high"),
    "440820ad-65b4-11d1-a3da-0000f875ae0d": ("Add-GUID",                             "low"),
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Manage-Topology",       "medium"),
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633": ("Create-Inbound-Forest-Trust",          "high"),
    "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": ("Enable-Per-User-Reversibly-Encrypted-Password", "low"),
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": ("Unexpire-Password",                    "low"),
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": ("Certificate-Enrollment",              "medium"),
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": ("Certificate-AutoEnrollment",          "low"),
}

# Well-known rights whose normal use is benign but which warrant more than "low"
# when hit — applied on top of the impacket name lookup.
_ELEVATED_NAMED_RIGHTS = {
    "Send-As": "medium",
    "Receive-As": "medium",
    "DS-Install-Replica": "medium",
    "Reanimate-Tombstones": "medium",
}


def extended_right_name(guid: str):
    """Resolve an extended-right GUID to (name, severity).

    Precedence:
      1. Our curated EXTENDED_RIGHTS (attack-relevant, with a deliberate severity).
      2. impacket's authoritative msada_guids.EXTENDED_RIGHTS (all 80 well-known
         rights), severity from _ELEVATED_NAMED_RIGHTS or "low".
      3. None — caller falls back to the live schema map, then the raw GUID.
    """
    g = (guid or "").lower()
    if g in EXTENDED_RIGHTS:
        return EXTENDED_RIGHTS[g]
    try:
        from impacket.msada_guids import EXTENDED_RIGHTS as _IMPACKET_ER
    except Exception:
        _IMPACKET_ER = {}
    name = _IMPACKET_ER.get(g)
    if name:
        return (name, _ELEVATED_NAMED_RIGHTS.get(name, "low"))
    return None

# DCSync requires both Get-Changes and Get-Changes-All on the domain head.
DCSYNC_PAIR = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
)

# ---------------------------------------------------------------------------
# Property-set / attribute GUIDs relevant when WRITE_PROP or READ_PROP is set.
# ---------------------------------------------------------------------------
WRITE_PROP_GUIDS = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": ("Member (add self/others to group)", "high"),  # member attr
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": ("gPLink (link GPOs to OU)",          "high"),
    "bf9679e8-0de6-11d0-a285-00aa003049e2": ("Public-Information (propset)",       "low"),
    "4c164200-20c0-11d0-a768-00aa006e0529": ("User-Account-Restrictions (propset)", "medium"),
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": ("User-Logon (propset)",              "low"),
    "77b5b886-944a-11d1-aebd-0000f80367c1": ("Personal-Information (propset)",     "low"),
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": ("DNS-Host-Name-Attributes (propset)", "medium"),
    "f3a64788-5306-11d1-a9c5-0000f80367c1": ("Service-Principal-Name (write SPN)", "high"),
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": ("msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)", "high"),
    "5b47d60f-6090-40b2-9f37-2a4de88f3063": ("msDS-KeyCredentialLink (shadow creds)", "high"),
}

# Validated-write GUIDs (DS_SELF bit + objtype).
VALIDATED_WRITES = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": ("Self-Membership (add self to group)", "high"),
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": ("Validated-DNS-Host-Name",             "medium"),
    "f3a64788-5306-11d1-a9c5-0000f80367c1": ("Validated-SPN (write SPN on self)",   "high"),
}

# LAPS / password-read attributes (READ_PROP with these objtype GUIDs is a
# read-secret capability). GUIDs are schema-dependent; matched by attribute name
# in the collector when the schema is available, but common defaults listed here.
LAPS_ATTR_NAMES = {
    "ms-mcs-admpwd",                 # legacy LAPS
    "mslaps-password",               # Windows LAPS
    "mslaps-encryptedpassword",
}

# ---------------------------------------------------------------------------
# Well-known SIDs — trustees that are "everyone-ish" and must be flagged, plus
# built-ins we resolve to friendly names when the object isn't in the store.
# ---------------------------------------------------------------------------
WELLKNOWN_SIDS = {
    "S-1-0-0":      "Null",
    "S-1-1-0":      "Everyone",
    "S-1-3-0":      "Creator Owner",
    "S-1-5-2":      "Network",
    "S-1-5-4":      "Interactive",
    "S-1-5-7":      "Anonymous",
    "S-1-5-9":      "Enterprise Domain Controllers",
    "S-1-5-11":     "Authenticated Users",
    "S-1-5-18":     "Local System",
    "S-1-5-19":     "Local Service",
    "S-1-5-20":     "Network Service",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-580": "BUILTIN\\Remote Management Users",
}

# Domain-relative RIDs (suffix on the domain SID) for built-in groups worth naming.
WELLKNOWN_RELATIVE = {
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "525": "Protected Users",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "500": "Administrator",
    "501": "Guest",
    "502": "krbtgt",
    "498": "Enterprise Read-only Domain Controllers",
    "521": "Read-only Domain Controllers",
    "553": "RAS and IAS Servers",
}

# "Broad" trustee SIDs — a control edge from any of these effectively means
# every user in the domain has that control. Flagged prominently.
BROAD_TRUSTEE_SIDS = {
    "S-1-1-0",    # Everyone
    "S-1-5-11",   # Authenticated Users
    "S-1-5-7",    # Anonymous
}
BROAD_TRUSTEE_RELATIVE = {"513", "515", "514"}  # Domain Users / Computers / Guests


def is_broad_trustee(sid: str) -> bool:
    if sid in BROAD_TRUSTEE_SIDS:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return sid.startswith("S-1-5-21-") and rid in BROAD_TRUSTEE_RELATIVE


# High-privilege built-in trustees whose control over infrastructure objects is
# by-design and not an attack path — used to flag "built-in noise" edges so the
# GUI can hide them. Absolute SIDs plus domain-relative RIDs.
BUILTIN_ADMIN_SIDS = {
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-18",      # Local System
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-551",  # Backup Operators
}
BUILTIN_ADMIN_RELATIVE = {
    "512",  # Domain Admins
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "516",  # Domain Controllers
    "498",  # Enterprise Read-only DCs
    "521",  # Read-only DCs
}


def is_builtin_admin_trustee(sid: str) -> bool:
    """True for the highly-privileged built-in groups/principals whose control
    over system/infrastructure objects is expected rather than a finding."""
    if sid in BUILTIN_ADMIN_SIDS:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return sid.startswith("S-1-5-21-") and rid in BUILTIN_ADMIN_RELATIVE


def wellknown_name(sid: str) -> str | None:
    """Friendly name for a SID from the well-known tables, or None."""
    if sid in WELLKNOWN_SIDS:
        return WELLKNOWN_SIDS[sid]
    if sid.startswith("S-1-5-21-"):
        rid = sid.rsplit("-", 1)[-1]
        if rid in WELLKNOWN_RELATIVE:
            return WELLKNOWN_RELATIVE[rid]
    return None
