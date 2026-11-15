from typing import Protocol
from pathlib import Path
from ..models import Task, RunConfig, RunOutput
class Runner(Protocol):
    async def run(self, task: Task, config: RunConfig, cwd: Path) -> RunOutput: ...
