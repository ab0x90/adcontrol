"""
adcontrol — Active Directory object-control / permission analyzer.

Given a principal (user / group / computer), maps every object it can control
across the domain (outbound) and every principal that can control it (inbound),
derived from AD object DACLs, transitive group membership, GPO-delivered rights,
and per-host RDP/logon rights.

This is a standalone, self-contained tool.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
