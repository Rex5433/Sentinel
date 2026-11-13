"""Run the pinned V5 checkpoint through the offline capture review path."""
import argparse
import json
from pathlib import Path

import torch

from scripts.v5_fresh_challenge import RUN
from sentinel.detection.offline_review import FORMATS, review_capture
from sentinel.detection.review_queue import TeamConfirmation
from sentinel.ingest.common import MAX_INPUT_BYTES
from training import diverse_experiment as v5
from training.experiment_data import ROOT


def local_path(value):
    path = value.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("Input, confirmation and output paths must stay inside V1")
    return path


def scorer():
    run, config, selected = v5.checked_run(RUN)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    model = v5._model().eval()
    model.load_state_dict(torch.load(run / "best.pt", weights_only=True, map_location="cpu")["state_dict"])
    norm = config["normalization"]
    mean, scale = torch.tensor(norm["mean"]), torch.tensor(norm["scale"])

    def score(vectors):
        values = (torch.tensor([vectors], dtype=torch.float32) - mean) / scale
        with torch.no_grad():
            return model(values.transpose(1, 2)).softmax(1)[0].transpose(0, 1).tolist()

    return score, selected["files"]["best.pt"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--format", choices=FORMATS, required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirmations", type=Path)
    parser.add_argument("--collection-complete", action="store_true", help="Attest the exported collection is complete for the observed interval")
    args = parser.parse_args()
    source, output = local_path(args.input), local_path(args.output)
    if output.exists():
        raise FileExistsError(f"Output already exists: {output}")
    confirmations = []
    if args.confirmations:
        entries = json.loads(local_path(args.confirmations).read_text(encoding="utf-8"))
        confirmations = [TeamConfirmation.model_validate(entry) for entry in entries]
    with source.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Capture exceeds the parser input limit")
    score, checkpoint = scorer()
    result = review_capture(raw, args.format, args.capture_id, source.name, score,
                            collection_complete=args.collection_complete, confirmations=confirmations)
    result["checkpoint_sha256"] = checkpoint
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
    print(json.dumps({key: value for key, value in result["queue"].items() if key != "items"}))


if __name__ == "__main__":
    main()
