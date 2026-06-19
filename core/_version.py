"""Single source of truth for the ProxyForce version string.

Bump this on every release and tag the repo `v<__version__>` (CI builds tag-driven
releases). `version_info.txt` (the Windows PE version resource) is bumped separately
as part of cutting a release.
"""

__version__ = "2.1.12"
