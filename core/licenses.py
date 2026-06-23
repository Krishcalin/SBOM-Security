"""License string -> SPDX identifier normalization.

Lockfiles and manifests spell licenses inconsistently ("Apache 2.0", "Apache
License, Version 2.0", "ASL 2.0" all mean Apache-2.0). Normalizing to SPDX IDs
makes license policy (Phase 5) and SPDX export reliable. Unknown values pass
through unchanged so nothing is silently dropped.
"""

from __future__ import annotations

_SPDX_MAP = {
    "mit": "MIT", "mit license": "MIT",
    "apache 2.0": "Apache-2.0", "apache-2.0": "Apache-2.0", "apache 2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0", "the apache software license, version 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause", "bsd-3-clause": "BSD-3-Clause", "new bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause", "bsd-2-clause": "BSD-2-Clause", "simplified bsd": "BSD-2-Clause",
    "isc": "ISC", "isc license": "ISC",
    "gpl-3.0": "GPL-3.0-only", "gplv3": "GPL-3.0-only", "gpl-2.0": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only", "lgpl-3.0": "LGPL-3.0-only", "lgpl-2.1": "LGPL-2.1-only",
    "mpl-2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
    "unlicense": "Unlicense", "the unlicense": "Unlicense", "cc0-1.0": "CC0-1.0",
    "python-2.0": "Python-2.0", "psf": "Python-2.0", "psf-2.0": "Python-2.0",
}


def normalize_spdx(raw: str | None) -> str:
    if not raw:
        return ""
    s = str(raw).strip()
    return _SPDX_MAP.get(s.lower(), s)
