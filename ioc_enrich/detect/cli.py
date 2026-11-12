"""Detection CLI: python -m ioc_enrich.detect <ioc> [<ioc>...] [--out DIR]"""
from __future__ import annotations
import argparse
import os
from .generate import generate_rules


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc_enrich.detect",
        description="Generate Sigma / YARA / Suricata detection rules from IOCs.")
    p.add_argument("iocs", nargs="+")
    p.add_argument("--context", default="", help="shared context/label for the rules")
    p.add_argument("--author", default="FarfallaJ")
    p.add_argument("--out", help="directory to write rule files into")
    args = p.parse_args(argv)
    items = [{"ioc": i, "context": args.context} for i in args.iocs]
    rs = generate_rules(items, author=args.author)

    if rs.sigma:
        print("# ===== SIGMA =====")
        print("\n---\n".join(rs.sigma))
    if rs.suricata:
        print("\n# ===== SURICATA =====")
        print("\n".join(rs.suricata))
    if rs.yara:
        print("\n# ===== YARA =====")
        print("\n\n".join(rs.yara))

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        if rs.sigma:
            with open(os.path.join(args.out, "rules.sigma.yml"), "w") as f:
                f.write("\n---\n".join(rs.sigma) + "\n")
        if rs.suricata:
            with open(os.path.join(args.out, "rules.suricata.rules"), "w") as f:
                f.write("\n".join(rs.suricata) + "\n")
        if rs.yara:
            with open(os.path.join(args.out, "rules.yara"), "w") as f:
                f.write("\n\n".join(rs.yara) + "\n")
        print(f"\n[rules written to {args.out}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
