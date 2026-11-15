from contextlib import contextmanager
from pathlib import Path
import tempfile, shutil

@contextmanager
def isolated_workspace(project: Path):
    # Reject links rather than following links outside the fixture.
    if any(p.is_symlink() for p in project.rglob('*')):
        raise ValueError('Project symlinks are unsupported for isolation')
    with tempfile.TemporaryDirectory(prefix='vulnbench-run-') as temp:
        target = Path(temp)/'project'
        shutil.copytree(project, target)
        yield target
