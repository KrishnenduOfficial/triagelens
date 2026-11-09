"""Run the curated Sigma pack against small synthetic mutations, offline."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.engine.rule_fragility import SyntheticCase, evaluate_fragility
from src.engine.sigma import load_curated_rules


def main() -> None:
    common = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    cases = [
        SyntheticCase("7be5fb68-f9ef-476d-8b51-0256ebece19e",
                      {**common, "Image": r"C:\Windows\System32\hostname.exe"}, ("Image",)),
        SyntheticCase("c6c56ada-612b-42d1-9a29-adad3c5c2c1e",
                      {**common, "CommandLine": "auditpol /logon:none"}, ("CommandLine",)),
    ]
    print(json.dumps(evaluate_fragility(load_curated_rules(), cases), indent=2))


if __name__ == "__main__":
    main()
