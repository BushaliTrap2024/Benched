import pytest


@pytest.fixture
def make_symlink():
    """Windows needs Developer Mode/admin rights for real symlinks."""
    def create(link, target, **kwargs):
        try:
            link.symlink_to(target, **kwargs)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f'Host cannot create test symlinks: {error}')
    return create
