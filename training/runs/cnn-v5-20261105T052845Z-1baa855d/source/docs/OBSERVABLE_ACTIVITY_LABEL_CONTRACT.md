# Observable activity label contract v1.0

November 4, 2026. Status: **reviewed design for a future candidate, not applied to
existing data or checkpoints**. The owner requested this contract review after
the matched-transition study. Implementation: `training/label_contract.py`;
schema boundary tests: `tests/unit/test_label_contract.py`. No data generation,
relabeling, training or inference runs in this milestone. MySQL remains deferred.

## What the CNN is being asked to learn

Recognize supported, observable activity patterns in Windows/Linux logs. Human
authorization is recorded separately and is never an input, target shortcut or
fifth output. The original causal 18→32→32→4 CNN and class ordering stay fixed.
Its current receptive field is the current five-minute window and at most four
prior windows. No future events, other hosts or disconnected sessions may supply
context. Features stay `event-window-v1` with the same schema hash and 18 values.

An account creation should have the SAME activity target whether an administrator
approved it or an attacker performed it. Approval changes the security context.
Conversely, a successful login using stolen valid credentials may have normal
observable activity and simulated-unapproved context. That combination is a known
detection gap, not a reason to invent a feature or force an authentication-burst
label. The model is not thereby learning general malicious-versus-benign truth.

## Four categories, precise supported scope

These are proposed annotation rules for the next candidate, not a claim that old
labels already follow them. Class IDs/names remain unchanged. The authentication
count rule below is an explicit operational definition for reproducible annotation,
not a statistical minimum or proof of attack. Freeze this rubric before generating
or reviewing the next candidate; changes require a new label version.

| ID / existing name | Observable target in v1.0 | Important exclusions |
| --- | --- | --- |
| 0 `normal_or_unremarkable` | Complete reviewed evidence contains none of the supported 1–3 patterns in this window under the causal rubric. Routine successful sessions, closes and ordinary sudo use can appear here. | Means none of these patterns observed, not authorized, safe or complete threat coverage. Missing/unrecognized evidence must not default here. |
| 1 `authentication_burst` | At least five parsed authentication failures in the current window; OR at least five failures across up to five contiguous observed windows, distributed over at least two failure-bearing windows, with at least one failure in the CURRENT window. | Includes approved retry bursts. Isolated failures below this rubric are not automatically a burst or malicious. Requires raw event evidence and per-window counts; no future knowledge of a later burst. |
| 2 `account_or_privilege_change` | At least one explicitly observed account creation supported by current account_created evidence and its count. | Approved creation stays class 2. Windows 4672 special-privilege assignment to a logon and ordinary sudo commands do not establish persistent account/permission modification. Deletions, group/grant/permission changes not distinguished by current features are out of the supported scope. |
| 3 `process_or_service_anomaly` | Explicit service installation or start/stop/state-transition evidence in current normalized service_installed, service_state_change or service_activity records. | Includes approved maintenance. The legacy name does not mean proven abnormality or compromise. Generic process behavior, arbitrary status text and service configuration edits not represented by these counts are outside current learned coverage. |

This deliberately narrows what class 2/3 can substantiate with today's features;
it does not remove their output categories. Richer privilege/process coverage
would need a separately reviewed parser/feature contract, not relabeling an
undifferentiated other_event_count as proof of those changes.

The count-based authentication rubric and presence-based account/service targets
are observable proxies. A rule baseline implementing these same definitions can
score highly by construction. CNN agreement with those proxies is not independent
attack-detection evidence, nor proof the CNN adds value over rules. Keep semantic
activity evaluation separate from security-context escalation evaluation.

## Ambiguity, mixed activity and incomplete evidence

Annotations have `label_status` and a nullable `observable_activity`:

- **supported:** exactly one reviewed category, including normal when justified.
- **mixed_activity:** multiple supported activity families in the SAME current
  window; record all families, target null. No priority rule silently picks one.
- **insufficient_evidence:** incomplete collection, missing identity/time, parse
  gaps, uncertain labels or inadequate causal coverage; target null.
- **feature_unobservable:** relevant raw/scenario facts are not distinguishable
  using the 18 inputs; target null. Retain these cases in a limitation/challenge
  inventory rather than claiming the CNN covers them.

Null targets are review metadata and eventual loss masks, NOT a fifth class.
Exclude masked windows from ordinary four-class loss/accuracy, but retain and
report them in coverage and escalation evaluation. Do not silently discard entire
difficult scenarios, relabel them normal or drop them from the reported denominator.
Normal+non-normal is not a valid observed-category combination; routine background
alongside one supported activity does not make it a two-class example.

Start/stop of a scenario does not dictate labels: each current window is reviewed
from current/prior evidence. A later window with no new burst/change may have a
normal activity target while incident review remains open. The label is about new
observations, not whether the host is now secured. Do not label a prefix from the
known outcome of the full synthetic scenario.

After a collection gap, host/session boundary or nonconsecutive five-minute slot,
reset context. Do not fill missing observations with fabricated zero events.
Document known-complete empty slots separately; the current feature extractor
does not emit empty windows. Start-of-capture/short-history windows need an explicit
coverage/warm-up policy in the next loader. Prefixes cannot be called complete
just because the generator knows what happened outside the captured interval.
The annotation validator checks references and shapes; the future loader must
check actual same-host/session chronology, completeness and raw-evidence facts.

## Separate security context and provenance

`authorization` has independent status, basis, evidence references, rationale and
reviewer. Never infer authorization from a model score, rule hit, missing alert,
known username, class name or absence of an attack label.

| Status | Required basis |
| --- | --- |
| authorized | Documented scenario approval or named human review with evidence; scenario approval remains declared simulation context, not field confirmation. |
| simulated_unapproved | Explicit team scenario manifest; never described as a confirmed real incident. |
| confirmed_unapproved | Named human review backed by evidence from team-collected data; not permitted for synthetic origin. |
| unknown | No established approval determination; unavailable evidence stays unknown. This does not by itself invalidate an observable activity target. |
| mixed | Evidence supports multiple authorization contexts; keep the mixture explicit. |

Each annotation also records label/feature versions, feature-schema hash, source
hash, current/causal window IDs, exact event IDs, activity-evidence references,
scenario group, split, review status and reviewer. These are audit metadata only.
`training_target()` returns an ID only for a reviewed supported annotation. That
result is NOT a training approval and does not replace evidence/split checks.
The schema cannot verify that a reviewer or cited source is truthful; source
resolution and independent review remain required in candidate preparation.

## Leakage and collision gates for the next candidate

1. Keep all approval counterparts, shared seeds/templates/source runs and their
   derivatives in the same independent scenario split group. Use whole groups for
   train/validation/test; do not split by row or five-minute window. Fit scaling
   on training inputs only. Group counts/coverage must be measured, not assumed.
2. Keep authorization, scenario IDs/names, target text, filenames, literal
   identifiers, reviewer fields and generator context out of the 18-feature input.
   Keep prospective scoring inputs separate from annotation sidecars.
3. Use `conflicting_contexts()` to quarantine identical complete causal inputs
   with differing reviewed targets; resolve annotation mistakes or record genuine
   ambiguity. Never majority-vote, relabel or assign duplicates across splits to
   conceal the conflict. It checks exact collisions only; source duplication,
   near-identical trajectories and shortcut audits remain separate requirements.
4. Do not copy the consumed V3 final test, fresh challenge or transition study
   records into a new candidate or treat them as fresh final evaluation. Publish
   fresh held-out scenario groups; report procedural versus field independence.
5. Preserve existing V2/V3 raw data, labels, hashes, loaders, checkpoints and
   metrics. A new candidate must pin this label version and source, feature and
   contract hashes. Old checkpoints retain their original label semantics even
   though the four output names match; do not reinterpret them under this version.
6. A future mixed-session loader must preserve chronological inputs while masking
   unsupported target slots. Current legacy loaders/trainers do not implement that
   mask or this schema. Do not feed these annotations to an unchanged legacy runner.

## What was reviewed, and what comes next

The consumed transition study found 18 identical approval-pair trajectories with
72 conflicting contextual targets; it also found the frozen CNN predicted normal
throughout. This contract removes the demand to infer approval from identical
observations for FUTURE annotation. It does not fix the old model, guarantee zero
false negatives, or provide new performance metrics. See
`docs/TRANSITION_AND_TARGET_REVIEW.md` for actual prior evaluation results.

Next atomic task: prepare and test a new, versioned mixed-session candidate
generator/loader using this contract, independent split groups, mask reporting,
source provenance and exact/near-duplicate audits. Include approved and simulated
unapproved matched activity, sparse bursts, transitions and unresolved blind
spots. Audit actual retained/masked counts by OS/class/group before any training.
No dataset was generated or migrated during this contract review. Training stays
explicitly approval-gated and owner-run; dashboard integration stays disabled.

## Actual validation for this milestone

- `python -m pytest -q tests/unit/test_label_contract.py tests/unit/test_candidate_v3_experiment.py tests/unit/test_transition_observability.py`: **54 passed**, including 33 new contract cases. One non-failing PyTorch warning: optional NumPy is absent.
- `python -m pytest -q tests/unit/test_features.py`: **12 passed**.
- `python scripts/smoke_test.py`: **PASS**, including sign-in, log/evidence analysis, PCAP, snapshot comparison, copy-only recovery/reports, deletion and logout. Learned AI/scored use stayed disabled.
- Rechecked the V3 manifest hash: `26123f7676adba49fbc69c95f617f15601470f776a073dd2e77e11bafb0f4a36`.
- Rechecked the frozen V3 checkpoint hash: `45d964f27a85ce24cef915afcd5eb0475cdd50f844a900af05e4ecf602f03e0a`.

All commands used V1's existing Python environment and temporary paths inside
V1. These were targeted checks, not a full-suite run. Schema tests use in-memory
hand-authored contract examples, not a new training dataset. Existing loader
tests perform loading and an untrained forward-pass check; no optimization or
new trained checkpoint occurs. The schema validates annotation consistency, not
the factual truth of a referenced scenario or full automatic rubric compliance.
No new precision/recall/F1 or confidence calibration results are claimed.
