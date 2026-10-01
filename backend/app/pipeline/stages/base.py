"""Pipeline stage contract."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.investigation import StageName
from app.pipeline.context import InvestigationContext


class Stage(ABC):
    name: StageName

    @abstractmethod
    async def run(self, ctx: InvestigationContext) -> str | None:
        """Execute the stage. Return an optional completion message."""
