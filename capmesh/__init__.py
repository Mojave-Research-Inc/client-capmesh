"""Client Capability Mesh (client-capmesh).

Baseline capability router for customer distribution, derived from ASG
Capability Mesh. Ships with a bundled capability set for customer installs.



The mesh indexes capability packages and exposes a fixed lazy-loading router
surface: cap.search, cap.load, cap.call, cap.list, cap.describe, cap.delegate,
and cap.report.
"""

from .models import Capability, Principal

__all__ = ["Capability", "Principal"]

