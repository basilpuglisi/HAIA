"""
HAIA Agent Framework - Platform Selector
==========================================
Implements the anchor-plus-rotation protocol specified in the
HAIA-RECCLIN Agent Architecture.

Each task dispatches to a minimum of three independent AI platforms:
    - One ANCHOR for longitudinal consistency
    - At least two from a ROTATION POOL, selected per task

The selector does not choose based on content quality or preference.
It follows the configured schedule. Platform selection is a governance
decision, not a cognitive one.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from .models import RECCLINRole
from .adapters import PlatformAdapter
from .security import SecureRotationSeed


@dataclass
class PlatformSelection:
    """Result of platform selection for a single task dispatch."""
    anchor: PlatformAdapter
    rotation: list[PlatformAdapter]
    rotation_seed: str = ""  # Logged for reconstruction (V9)
    all_platforms: list[PlatformAdapter] = field(default_factory=list)

    def __post_init__(self):
        self.all_platforms = [self.anchor] + self.rotation


class PlatformSelector:
    """
    Selects platforms for each dispatch using anchor-plus-rotation.

    Configuration:
        - Register available adapters
        - Assign anchors per RECCLIN role (or global default)
        - Set minimum rotation count (default: 2, spec minimum: 2)
        - Rotation selection uses round-robin or random per config

    Non-cognitive constraint: Selection is based on schedule and
    configuration, never on content evaluation or response quality.
    """

    def __init__(self, min_rotation: int = 2):
        self._adapters: dict[str, PlatformAdapter] = {}
        self._role_anchors: dict[RECCLINRole, str] = {}
        self._default_anchor: Optional[str] = None
        self._min_rotation = max(2, min_rotation)  # Spec minimum is 2
        self._rotation_index: int = 0

    def register_adapter(self, adapter: PlatformAdapter) -> None:
        """Register a platform adapter as available for selection."""
        self._adapters[adapter.platform_id] = adapter

    def set_anchor(
        self,
        platform_id: str,
        role: Optional[RECCLINRole] = None,
    ) -> None:
        """
        Set the anchor platform for a specific role or as global default.

        The anchor provides longitudinal consistency: the same platform
        handles the same role across tasks so behavioral drift is detectable.

        Args:
            platform_id: Must match a registered adapter's platform_id
            role: Specific RECCLIN role, or None for global default
        """
        if platform_id not in self._adapters:
            raise ValueError(
                f"Platform '{platform_id}' not registered. "
                f"Available: {list(self._adapters.keys())}"
            )
        if role:
            self._role_anchors[role] = platform_id
        else:
            self._default_anchor = platform_id

    def select(self, role: RECCLINRole) -> PlatformSelection:
        """
        Select platforms for a task dispatch.

        Returns an anchor and rotation platforms totaling at least 3.

        Selection logic:
            1. Anchor: role-specific if set, otherwise global default,
               otherwise first registered adapter
            2. Rotation: all other registered adapters except the anchor,
               limited to min_rotation count

        Raises ValueError if fewer than 3 platforms are registered.
        """
        if len(self._adapters) < 3:
            raise ValueError(
                f"Minimum 3 platforms required. "
                f"Currently registered: {len(self._adapters)} "
                f"({list(self._adapters.keys())})"
            )

        # Resolve anchor
        anchor_id = self._role_anchors.get(role, self._default_anchor)
        if anchor_id is None:
            anchor_id = list(self._adapters.keys())[0]

        anchor = self._adapters[anchor_id]

        # Build rotation pool: all adapters except anchor
        rotation_pool = [
            adapter for pid, adapter in self._adapters.items()
            if pid != anchor_id
        ]

        # Select rotation members
        # Use deterministic round-robin offset for reproducibility,
        # but ensure at least min_rotation are selected
        rotation_count = min(self._min_rotation, len(rotation_pool))
        start = self._rotation_index % len(rotation_pool)
        selected_rotation = []
        for i in range(rotation_count):
            idx = (start + i) % len(rotation_pool)
            selected_rotation.append(rotation_pool[idx])
        self._rotation_index += 1

        return PlatformSelection(
            anchor=anchor,
            rotation=selected_rotation,
        )

    def get_registered_platforms(self) -> list[str]:
        """Return IDs of all registered platform adapters."""
        return list(self._adapters.keys())

    def get_adapter(self, platform_id: str) -> Optional[PlatformAdapter]:
        """Get a specific adapter by platform ID."""
        return self._adapters.get(platform_id)

    def secure_select(self, role: RECCLINRole, task_id: str = "") -> PlatformSelection:
        """
        Select platforms using cryptographic randomization (V9).

        Same as select() but uses a cryptographic seed for rotation
        instead of deterministic round-robin. The seed is included
        in the PlatformSelection for audit trail logging.

        An adversary cannot predict which platforms will be selected
        because the seed is generated from /dev/urandom. The seed
        is logged so selections are reconstructable from the audit trail.

        Args:
            role: RECCLIN role for this task
            task_id: Transaction or task identifier for per-task uniqueness
        """
        if len(self._adapters) < 3:
            raise ValueError(
                f"Minimum 3 platforms required. "
                f"Currently registered: {len(self._adapters)} "
                f"({list(self._adapters.keys())})"
            )

        # Resolve anchor (same logic as select)
        anchor_id = self._role_anchors.get(role, self._default_anchor)
        if anchor_id is None:
            anchor_id = list(self._adapters.keys())[0]
        anchor = self._adapters[anchor_id]

        # Build rotation pool
        rotation_pool = [
            adapter for pid, adapter in self._adapters.items()
            if pid != anchor_id
        ]

        # Cryptographic random selection (V9)
        seed = SecureRotationSeed.generate_seed()
        rotation_count = min(self._min_rotation, len(rotation_pool))
        selected = SecureRotationSeed.select_rotation(
            pool=rotation_pool,
            count=rotation_count,
            seed=seed,
            task_id=task_id,
        )

        return PlatformSelection(
            anchor=anchor,
            rotation=selected,
            rotation_seed=seed,
        )
