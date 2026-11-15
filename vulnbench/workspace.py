from contextlib import contextmanager
from pathlib import Path
import os
import stat
import tempfile
import shutil


def _is_link_or_reparse_point(path: Path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


@contextmanager
def isolated_workspace(project: Path):
    # Reject Windows junctions/reparse points as well as Unix/Windows symlinks.
    # Check every directory before walking into it; rglob can follow junctions.
    if _is_link_or_reparse_point(project):
        raise ValueError('Project symlinks/reparse points are unsupported for isolation')
    for directory, directories, files in os.walk(project, followlinks=False):
        if any(_is_link_or_reparse_point(Path(directory) / name) for name in directories + files):
            raise ValueError('Project symlinks/reparse points are unsupported for isolation')
    with tempfile.TemporaryDirectory(prefix='vulnbench-run-') as temp:
        target = Path(temp) / 'project'
        shutil.copytree(project, target)
        yield target
