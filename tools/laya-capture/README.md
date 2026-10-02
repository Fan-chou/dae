# Capture audit tools

See [the capture guide](../../docs/zh/passive-capture.md) for configuration, field provenance, cursor handling and limitations.

- `capture.schema.json`: transport schema; it is deliberately not `kdae-evidence-v4.1`.
- `validate.py`: strict keys, types and cross-field checks, missingness by stage, mandatory model abstention.
- `archive.py`: immutable JSONL and SHA-256 manifest, pending review, no generated gold, 100 MiB/day budget.
- Tests: `python3 -m unittest discover -s tools/laya-capture -v`.

Artifacts must remain linked to the binary SHA, capture generation, sampling configuration, and capture time. A raw window is not an independent root-cause episode. Keep natural sampling separate from future fault-enriched data. Do not reuse V4 synthetic labels or calibration thresholds for these records.

## Evidence sidecar

See [evidence collection and correlation](../../docs/zh/evidence-correlation.md).

- `evidence.schema.json`, `evidence.py`: typed sidecar facts, conservative candidate links and decision-time cutoff.
- `smartdns_evidence.py`: in-memory keyed redaction of SmartDNS audit lines; no invented RCODE/cache/filter cause.
- `collect_evidence.py`: bounded SSH pagination, validated immutable archives, durable cursor, binary provenance and gaps.
- `annotations.py`: review provenance, citations, disagreements and incident split validation across all supplied annotation files; reviewer identities are normalized. Pass every related annotation file in one invocation; never supplies gold labels.
- `read-observation.sh`: root-only authenticated read helper for 223; key/token never enters command arguments.

`deploy-223.sh` records the one-time 2026-09-26 deployment. Its binary hashes,
backup path and expected version are specific to that release; it refuses other
starting binaries. Use it only to reproduce that deployment. The 2026-10-02
quality build was deployed separately and is not installed by this script.
