# Candidate V5 owner-run protocol

Use `Start Candidate V5 Notebook.bat` on Windows and open
`notebooks/Run_Candidate_V5.ipynb`. **Run All defaults to preflight only.** The
launcher checks the existing V1 environment and starts JupyterLab on loopback;
it does not install packages or execute notebook cells. The Python 3 notebook
kernel must be from V1's `.venv`. On macOS use the V1 virtual environment and
start JupyterLab from the project root with `--ip=127.0.0.1`, keeping TEMP/TMPDIR,
IPYTHONDIR and Jupyter config/data/runtime directories under V1/tmp.

## Preflight and opt-in

The original dataset remains pending procedural review. The runner pins
`candidate-v5-e3bfbee69ae4` and these SHA-256 digests:

- Manifest: `04384711440d62e3b7c2de27eabb362b119e4f674012814a1c0f4968a80214be`
- Audit: `5c0ed2e9ef96e501a04d83f47098d6e519a0b89c1c44544b9c611e0413c086d9`

Preflight reparses train/validation exports through the versioned V5 loader,
validates the 8,192 / 2,048 selected anchors and their masks, and computes
normalization over **24,320 real observed train windows** only, before any
padding. That includes real context and masked observations. Zero-variance
features use scale 1. Gap segments remain separate. A randomly initialized
4,996-parameter CNN runs a small shape, causal-prefix and masked-loss check with
gradients off. No optimizer, training run, acceptance file, or test access occurs.
Data loading can take a few minutes. The CLI equivalent is:

```powershell
.\.venv\Scripts\python.exe -m training.diverse_experiment
```

Only after explicit training approval, set `APPROVE_V5_TRAINING=True` in the
notebook's **Optional owner-run training** cell and run it. This deliberate
owner action records corpus acceptance bound to both hashes. It does not change
pending labels on disk or attest to individual field truth. `owner_run` has no
implicit opt-in; command-line module execution remains preflight only.

## Frozen experiment and outputs

Use the existing causal 18→32→32→4 CNN, randomly initialized with seed 84, on
local CPU, deterministic algorithms and one PyTorch thread. Adam uses learning
rate 0.001 and weight decay 0.0001; batches contain up to 16 contiguous segments.
Stop at 200 epochs or after 25 without a validation-loss improvement of 0.0001.
Save the checkpoint with the lowest observed validation loss. Training loss and
four-class metrics count only the selected anchors; other observed windows and
right padding do not contribute targets. Normalization is never refit using
validation or test.

Under V1/training/runs the runner saves a corpus-bound exclusive claim, acceptance
record, configuration, environment versions, source snapshots/hashes, initial,
best and last checkpoints, epoch loss/F1 history and selected-checkpoint reports.
An existing completed run is reused. An incomplete claim stops for inspection;
do not remove it to trigger a silent restart. Notebook output need not be saved
to preserve artifacts.

Reports include loss, per-class precision/recall/F1, macro F1, confusion matrix,
OS breakdown, descriptive score diagnostics and activity false negatives,
precision, recall, F1 and F2. Comparison uses the older single-window threshold
baseline and the observable five-window rubric. The latter mirrors labels by
construction. Binary activity review counts any non-normal prediction as a
review; a wrong non-normal subtype still counts as a multiclass error. These are
synthetic activity metrics, not field authorization or incident-detection
probabilities. Full-context backup verification is a separate evaluation.

## Test is separate

After reviewing the saved training/validation results and selected checkpoint,
explicitly accept the final evaluation by setting `ACCEPT_SELECTED_FOR_TEST=True`
in the final cell. The runner checks the saved source/config/checkpoint hashes and
writes an exclusive test-start marker **before** loading the 2,048 selected
reserved test anchors. It saves test metrics and a completion hash. Re-entry
shows where results are saved; any partial attempt stays locked. Do not use test
results to select another checkpoint or tune this experiment. No dashboard
deployment or competition use is enabled by this notebook.

## Verified before release to the owner

The default **Run All** completed in a real local Jupyter kernel using the
actual pinned candidate. `Start Candidate V5 Notebook.bat --check` also passed.
The executed check is saved separately at `V1/tmp/candidate-v5-notebook-smoke.ipynb`;
the owner notebook remains clean. No V5 acceptance or training run files were
created, the optimizer was never constructed, and final-test inputs were closed.

| Checked on actual V5 data | Training | Validation |
|---|---:|---:|
| Selected targets | 8192 | 2048 |
| Observed windows | 24320 | 6080 |
| Observed windows excluded from target loss | 16128 | 4032 |
| Single-window rule macro F1 | 37.83% | 36.85% |
| Observable rubric macro F1 | 100.00% | 100.00% |

Normalization used only the 24,320 training observations. The untrained masked
sample passed with input shape `[2, 18, 88]` and output shape `[2, 4, 88]`,
including a separate seven-window segment padded on the right. The check verified
that later inputs cannot affect earlier logits and that the loss matches manual
selection of the target positions. The reported F1 values are **rules only**;
no trained V5 CNN result exists yet.

Nine targeted tests passed: approval gates, train/validation isolation, mask
integrity, metric counts, hash-bound acceptance, completed/partial run handling,
tamper rejection and the one-shot test. The run/final-test guard tests use mock
artifacts and dummy predictions, never optimize weights or use actual test data.

The full suite passed **1,711 tests, zero failures, five Linux-specific skips**
in 249.36 seconds. Two existing warnings concern optional NumPy and the
Starlette/httpx test client. The application loopback smoke passed with learned
inference and scored use disabled. The existing V4 checkpoint and V5 corpus
pins were rechecked and are unchanged.
