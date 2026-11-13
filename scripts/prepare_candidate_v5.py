"""Explicit original-data preparation and audit; never imports a model/trainer."""
import argparse
import json

from training.diverse_candidate import generate
from training.diverse_data import audit
from training.experiment_data import hashfile


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate",action="store_true")
    args=parser.parse_args()
    if not args.generate:
        print("Explicit --generate required. No training.")
    else:
        folder=generate()
        print("CANDIDATE",folder,flush=True)
        pin=hashfile(folder/"manifest.json")
        report=audit(folder,pin)
        with (folder/"audit.json").open("x",encoding="utf-8") as stream:
            json.dump(report,stream,indent=2,allow_nan=False)
        with (folder/"complete.json").open("x",encoding="utf-8") as stream:
            json.dump(dict(manifest_sha256=pin,audit_sha256=hashfile(folder/"audit.json"),training_started=False),stream,indent=2)
        print("RESULT",json.dumps({k:report[k] for k in ("status","events","windows","selected_targets","all_supported_windows","masked_windows","independent_procedural_groups","recipe_parameter_families","near_duplicate_source_pairs")}),flush=True)
