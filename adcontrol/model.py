"""
Normalized in-memory object store.

This is the *seam* that makes offline analysis cheap: the live LDAP collector
populates an ``ObjectStore``, and every downstream module (graph, analyze,
report, GUI) reads only from the store — never from LDAP directly. An offline
parser (ldapdomaindump / BloodHound zip / LDIF) just has to populate the same
store to get the entire analysis pipeline for free.

Nothing here imports ldap3 or impacket — it is pure data.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Ace:
    """One parsed access-control entry on an object's DACL, already resolved to
    a named right by the SD parser."""
    trustee_sid: str            # SID the ACE grants to
    right: str                  # human-readable right name, e.g. "GenericAll", "DCSync", "ForceChangePassword"
    severity: str               # "high" | "medium" | "low"
    applies_to: str = ""        # object-type GUID/name the right is scoped to, "" = whole object
    ace_flags: int = 0          # raw ACE flags (inheritance)
    inherited: bool = False     # True if this ACE was inherited from a parent
    raw_mask: int = 0           # raw access mask (for debugging / detail view)


@dataclass
class RawObject:
    """A single AD object as normalized into the store."""
    dn: str
    sid: str = ""                       # objectSid as S-1-5-... ("" for objects without a SID, e.g. OUs/GPOs)
    guid: str = ""                      # objectGUID
    sam: str = ""                       # sAMAccountName
    name: str = ""                      # cn / display name
    object_class: str = ""              # most-specific: user | group | computer | organizationalUnit | groupPolicyContainer | container | domain
    classes: list[str] = field(default_factory=list)  # full objectClass list
    aces: list[Ace] = field(default_factory=list)      # parsed DACL
    owner_sid: str = ""                 # SD owner
    members: list[str] = field(default_factory=list)   # member DNs (groups)
    member_of: list[str] = field(default_factory=list) # memberOf DNs
    gplinks: list[str] = field(default_factory=list)   # linked GPO DNs (OUs/domain)
    admin_count: int = 0
    uac: int = 0                        # userAccountControl
    enabled: bool = True
    extra: dict = field(default_factory=dict)          # attribute overflow (spn, laps flags, os, etc.)

    @property
    def label(self) -> str:
        return self.sam or self.name or self.dn


@dataclass
class PolicyRight:
    """A right delivered by GPO or found on a host that is NOT an AD-object DACL
    edge — e.g. 'Allow log on through RDP', local-admin membership, Restricted
    Groups. Kept in its own list so it never mixes with the ACL control graph.

    ``plane`` is 'gpo' or 'host'. ``trustees`` are the SIDs/names granted the
    right; ``applies_to`` describes the scope (an OU DN, a computer name, or a
    GPO-linked container)."""
    plane: str                  # "gpo" | "host"
    right: str                  # e.g. "SeRemoteInteractiveLogonRight (Allow log on through RDP)"
    trustees: list[str] = field(default_factory=list)   # resolved display labels granted
    trustee_sids: list[str] = field(default_factory=list)  # canonical SIDs (parallel to trustees; for SID-based joins)
    applies_to: str = ""        # OU DN / computer / GPO name
    applies_to_sid: str = ""    # SID of the host/target object when known (for SID-based joins)
    source: str = ""            # GPO display name or host FQDN
    severity: str = "medium"
    detail: str = ""


@dataclass
class ControlEdge:
    """A directed control relationship: source principal controls target object
    via a specific right. Direction is decided by the caller (analyze.py) and the
    same dataclass is reused for both outbound and inbound result sets, which are
    NEVER merged."""
    source_sid: str
    source_label: str
    target_dn: str
    target_label: str
    target_class: str
    right: str
    severity: str
    applies_to: str = ""
    via: str = ""          # how the source holds it: "direct" or "group: <group label>"
    inherited: bool = False
    broad: bool = False     # source is Everyone / Authenticated Users / Domain Users etc.
    builtin_noise: bool = False  # built-in admin controlling a system/infra object (expected, hideable)


@dataclass
class Session:
    """A user logged on to a computer at collection time (BloodHound HasSession).

    ``kind`` records the collection method's confidence: 'privileged' (LSASS /
    high-integrity) and 'registry' (HKU enumeration) are reliable — the user's
    credentials are actually on the host; 'netsession' (net session enumeration)
    is looser and can be stale, so it's kept informational and NOT chained into
    attack paths."""
    user_sid: str
    computer_sid: str
    kind: str = "netsession"    # "privileged" | "registry" | "netsession"


@dataclass
class AdcsFinding:
    """One ADCS misconfiguration (ESC*) on a certificate template or CA.

    Kept in its own list (``store.adcs_findings``) so it never mixes with the AD
    object-control graph. ``enrollers`` are the resolved principal labels who can
    enroll (or, for ESC4, control) the template — the actors who can abuse it."""
    esc: str                    # "ESC1" | "ESC2" | "ESC3" | "ESC4" | "ESC6" | ...
    template: str               # template display name
    template_dn: str = ""
    severity: str = "high"
    ca: str = ""                # issuing CA display name (when known)
    enrollers: list = field(default_factory=list)      # principal labels who can enroll/control
    enroller_sids: list = field(default_factory=list)  # parallel SIDs (for joins)
    detail: str = ""            # human explanation of the condition
    reasons: list = field(default_factory=list)        # the specific flags that made it vulnerable


class ObjectStore:
    """All collected objects plus SID/DN indexes and a domain-info record.

    Populated by collector.py (live) or an offline parser. Consumed read-only by
    graph.py / analyze.py / report.py / app.py.
    """

    def __init__(self) -> None:
        self.objects: dict[str, RawObject] = {}      # keyed by DN (canonical)
        self._by_sid: dict[str, str] = {}            # sid -> dn
        self.policy_rights: list = []                # list[PolicyRight] from GPO/host planes
        self.sessions: list = []                     # list[Session] user↔host logon sessions
        self.adcs_findings: list = []                # list[AdcsFinding] ESC* misconfigs
        self.domain: str = ""
        self.domain_sid: str = ""
        self.base_dn: str = ""
        self.schema_guid_names: dict[str, str] = {}  # objtype GUID -> attribute/class friendly name
        self.collected_at: str = ""
        self.source: str = "live-ldap"               # or "offline:<kind>"
        self.meta: dict = field(default_factory=dict) if False else {}
        # Lazily-built session indexes (see build_session_indexes()).
        self._sessions_on_host: dict = {}            # computer_sid -> list[Session]
        self._user_sessions: dict = {}               # user_sid -> list[Session]

    def __setstate__(self, state: dict) -> None:
        """Unpickle-safe: fill in attributes added after a pickle was written so
        older saved sessions (pre-``sessions`` support) load without AttributeError."""
        self.__dict__.update(state)
        self.__dict__.setdefault("sessions", [])
        self.__dict__.setdefault("adcs_findings", [])
        self.__dict__.setdefault("_sessions_on_host", {})
        self.__dict__.setdefault("_user_sessions", {})

    # -- population -----------------------------------------------------------
    def add(self, obj: RawObject) -> None:
        # DN is the canonical key; normalize case-insensitively for indexing.
        key = obj.dn
        self.objects[key] = obj
        if obj.sid:
            self._by_sid[obj.sid] = key

    # -- lookup ---------------------------------------------------------------
    def by_dn(self, dn: str) -> RawObject | None:
        obj = self.objects.get(dn)
        if obj is not None:
            return obj
        # Case-insensitive fallback (AD DNs are case-insensitive).
        low = dn.lower()
        for k, v in self.objects.items():
            if k.lower() == low:
                return v
        return None

    def by_sid(self, sid: str) -> RawObject | None:
        dn = self._by_sid.get(sid)
        return self.objects.get(dn) if dn else None

    def find(self, term: str) -> list[RawObject]:
        """Loose search by sAMAccountName / name / DN / SID substring."""
        t = term.lower()
        out = []
        for obj in self.objects.values():
            if (t in obj.sam.lower() or t in obj.name.lower()
                    or t in obj.dn.lower() or t == obj.sid.lower()):
                out.append(obj)
        return out

    def principals(self) -> list[RawObject]:
        """Objects that can be a chosen subject: users, groups, computers."""
        return [o for o in self.objects.values()
                if o.object_class in ("user", "group", "computer")]

    # -- sessions -------------------------------------------------------------
    def build_session_indexes(self) -> None:
        """(Re)build the host↔user session indexes from ``self.sessions``. Called
        after population; safe to call repeatedly."""
        self._sessions_on_host = {}
        self._user_sessions = {}
        for s in self.sessions:
            self._sessions_on_host.setdefault(s.computer_sid, []).append(s)
            self._user_sessions.setdefault(s.user_sid, []).append(s)

    def sessions_on_host(self, computer_sid: str) -> list:
        """Sessions (users logged on) for a computer SID."""
        if self.sessions and not self._sessions_on_host:
            self.build_session_indexes()
        return self._sessions_on_host.get(computer_sid, [])

    def sessions_of_user(self, user_sid: str) -> list:
        """Sessions (hosts) a user is logged on to."""
        if self.sessions and not self._user_sessions:
            self.build_session_indexes()
        return self._user_sessions.get(user_sid, [])

    def __len__(self) -> int:
        return len(self.objects)
