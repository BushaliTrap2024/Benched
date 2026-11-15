from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict

class Finding(BaseModel):
    type: str
    file: str = ''
    line: int | None = None
    severity: Literal['critical','high','medium','low'] = 'medium'
    description: str = ''
    id: str | None = None

class References(BaseModel):
    description: str
    vulnerabilities: list[Finding]
    def validate_ids(self):
        ids = [f.id for f in self.vulnerabilities]
        if any(not i for i in ids) or len(ids) != len(set(ids)):
            raise ValueError('Reference IDs must be nonempty and unique')
        return self

class RunConfig(BaseModel):
    model_config = ConfigDict(extra='allow')
    id: str
    name: str = ''
    type: Literal['model','command'] = 'model'
    model: str | None = None
    effort: str = 'high'
    maxTurns: int = Field(30, gt=0)
    timeoutMs: int = Field(600000, gt=0)
    allowedTools: list[str] = Field(default_factory=lambda: ['Read','Glob','Grep','Bash','Write','Edit'])
    structuredOutput: bool = False

class Task(BaseModel):
    id: str
    name: str
    fixture: str
    category: Literal['find-vulns']
    systemPrompt: str
    prompt: str
    maxTurns: int | None = Field(None, gt=0)

class RunOutput(BaseModel):
    final_text: str = ''
    findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    failure: str | None = None
    error: str | None = None
