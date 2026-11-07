# Candidate V5 preparation protocol

New original team-generated synthetic telemetry only. Preserve the existing CNN,
four class IDs, observable-activity-v1.0 label contract, event-window-v1's 18
features and all earlier artifacts. No training or checkpoint inference in this
step. Preparation is explicit: `python -m scripts.prepare_candidate_v5 --generate`.
Output is a new UUID directory in V1/data/private; never overwrite a candidate.

## Planned corpus and separation

24 cadence/identity parameter families, eight replicates, two OS episodes per
group: 384 independent seeded OS sessions in 192 procedural groups. Six cadence
laws x four user/IP identity patterns define the families. The first four cadence
laws (16 families) are training; late-cluster cadence (four families) validation;
alternating-edge cadence (four families) final test. Both OS variants and all
replicates of a family remain together. Shared macros/renderer mean these are
procedural family splits, not independent field domains or unseen attack types.

Each source has 95 observed five-minute windows, one explicit missing interval,
and four randomly ordered activity blocks. Eight supported anchors per class per
session are proposed for primary supervision: 12,288 total, planned train 8,192,
validation 2,048, test 2,048. This is four times V4's 3,072 unique primary targets,
not a claim of a sufficient statistical sample size. The audit must measure actual
retained counts. All remaining observations and annotations are retained for
causal context, diagnostics and masking; do not count them as balanced anchors.

One export per OS session rotates Windows JSON/CSV and Linux text/journal JSON,
avoiding duplicate-format inflation. Some sources use BOM-marked UTF-16, time
offsets and IPv6. No original challenge records are reused or auto-merged.

## Activity variation and label integrity

- Authentication: concentrated counts, five consecutive singleton failures,
  distributed pairs, and distributed failures separated by quiet windows.
  Before reaching the documented threshold, observable labels remain normal.
- Account/service: one creation/install/state change amid quiet to 500+ event
  backgrounds, plus small/bulk counts and changing service states. Unique created
  account/install identities do not reuse an existing resource name.
- Difficult benign: isolated/recurring retries with at most four failures in any
  five-window context, routine sudo/special-privilege logons, busy successful
  sessions. Approved account/service activity remains its observable class.
- Equal primary background-load strata across all four classes within each OS
  session. This reduces load-as-label shortcuts; class-specific event counts are
  the intentional signal. Timing/identity laws are selected independently of class.
- Deliberate mixed targets, valid unsupported events, unlogged change and a missing
  interval remain visible. Warmup and four windows after gaps are masked; unknown
  records also mask every affected five-window causal input. No zero filling.

Labels come from latent event facts, checked against parser results and independent
18-value arithmetic, with a separate feature-side rubric agreement check. They
remain pending procedural proposals, not human-confirmed incidents. Authorization
is scenario metadata independent of the class target and excluded from features.
No reviewer status or training approval is fabricated.

## Audit and acceptance

Record raw/source/annotation hashes, generator/parser/feature/label versions and
source snapshots. Verify chronology, fact-to-record mapping, all 18 values,
expected unsupported events and masks, and exact eight-per-class anchors in every
session. The loader must reject tampering/path escapes/cross-split lineage and
must not open final-test raw data for train/validation loading. Reviewed training
target count remains zero; no trainer is wired to this corpus.

Report natural supported-window and balanced-anchor counts separately by class,
OS and split. Audit exact vectors, full causal contexts, label conflicts, whole
trajectories and near-identical sources. A timing-free behavioral hash drops span
and the derived failure fraction; shared behavior across splits is disclosed,
not concealed by timestamp jitter. Near-source distance uses training-only SD,
floored at one, across all observed vectors: max <=0.25 and mean <=0.02. This is
a documented limited similarity metric, not proof against all shortcuts.

Final-test inspection here is structural dataset QA only, with no CNN predictions,
threshold selection or fitting. After generation, freeze all sources; do not
revise examples using final-test model results. Report limitations and stop for
review before a new training run. These labels cannot recover missing evidence,
learn human authorization from identical vectors, or guarantee zero false negatives.
