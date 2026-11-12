"""Generate hash-based YARA rules from file-hash IOCs."""
from __future__ import annotations
import re
from datetime import date
from ..ioctypes import MD5, SHA1, SHA256, normalize

_HASH_FN = {MD5: "md5", SHA1: "sha1", SHA256: "sha256"}


def rule_for(ioc: str, ioc_type: str, author: str = "FarfallaJ",
             context: str = "", links: list[str] | None = None) -> str | None:
    if ioc_type not in _HASH_FN:
        return None
    h = normalize(ioc)
    fn = _HASH_FN[ioc_type]
    name = "Malicious_File_" + re.sub(r"[^A-Za-z0-9]", "", h)[:16]
    refs = (links or [])
    ref_line = f'\n        reference = "{refs[0]}"' if refs else ""
    desc = context or "File matching a known-malicious hash"
    return (
        'import "hash"\n\n'
        f"rule {name}\n{{\n"
        "    meta:\n"
        f'        description = "{desc}"\n'
        f'        author = "{author}"\n'
        f'        date = "{date.today().isoformat()}"\n'
        f'        {fn} = "{h}"{ref_line}\n'
        "    condition:\n"
        f"        hash.{fn}(0, filesize) == \"{h}\"\n"
        "}"
    )
