"""Masked-batch/causality readiness checks. No optimizer and no training entry point."""
import torch
from torch.nn import functional as F

from training.experimental_cnn import SentinelCNN
from training.experiment_data import normalize_fit
from training.mixed_data import IGNORE_TARGET, load


def tensors(sessions, norm, *, proposals=False):
    if not sessions:
        raise ValueError("No sessions")
    length = max(len(s["vectors"]) for s in sessions)
    x = torch.zeros(len(sessions), 18, length)
    y = torch.full((len(sessions), length), IGNORE_TARGET, dtype=torch.long)
    mean, scale = torch.tensor(norm["mean"]), torch.tensor(norm["scale"])
    for i, session in enumerate(sessions):
        rows = torch.tensor(session["vectors"], dtype=torch.float32)
        targets = session["candidate_targets"] if proposals else session["targets"]
        if len(targets) != len(rows):
            raise ValueError("Target/input alignment mismatch")
        x[i, :, :len(rows)] = ((rows - mean) / scale).transpose(0, 1)
        y[i, :len(rows)] = torch.tensor(targets, dtype=torch.long)
    return x, y


def masked_loss(logits, targets):
    if not (targets != IGNORE_TARGET).any():
        raise ValueError("No reviewed/unmasked targets; refuse empty or unreviewed training loss")
    return F.cross_entropy(logits, targets, ignore_index=IGNORE_TARGET)


def self_check(folder, manifest_pin):
    """Untrained forward pass on TRAIN/VALIDATION proposals only, never final test."""
    sessions = load(folder, {"train", "validation"}, manifest_pin)
    training = [s for s in sessions if s["split"] == "train"]
    norm = normalize_fit(training)
    # Pick different lengths to exercise right padding without bridging any gaps.
    sample = [training[0], training[1]]
    torch.manual_seed(84)
    model = SentinelCNN().eval()
    x, y = tensors(sample, norm, proposals=True)
    with torch.no_grad():
        before = model(x)
        changed = x.clone()
        changed[:, :, 5:] += 100
        if not torch.equal(before[:, :, :5], model(changed)[:, :, :5]):
            raise ValueError("Future input leaked into earlier outputs")
        loss = masked_loss(before, y)
    if not torch.isfinite(loss):
        raise ValueError("Nonfinite masked proposal loss")
    _, actual_targets = tensors(sample, norm)
    if (actual_targets != IGNORE_TARGET).any():
        raise ValueError("Pending review unexpectedly became approved training targets")
    return dict(status="passed", parameters=sum(p.numel() for p in model.parameters()),
                architecture="Original SentinelCNN, causal 18-32-32-four outputs",
                fit_training_windows=norm["fit_windows"], input_shape=list(x.shape), output_shape=list(before.shape),
                proposal_loss_is_finite=True, reviewed_training_targets=0,
                optimizer_created=False, training_started=False, final_test_inputs_loaded=False,
                note="An untrained forward/shape/mask check is not a model performance result or training approval.")
