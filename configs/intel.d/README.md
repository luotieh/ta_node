# intel.d — IOC overlay drop-in directory

Every `*.yaml` / `*.yml` file in this directory is loaded (concurrently) and
merged into the in-memory IOC set alongside the primary `intel_file`
(`configs/intel.yaml`). This lets you:

- **Split a large IOC list** across many small files instead of one giant file.
- **Add IOCs incrementally** by dropping in a new file (e.g. one per feed or per
  batch) — no need to edit existing files.
- **Hot-reload**: with `intel.enable_hot_reload: true`, new/changed files are
  picked up within `intel.reload_interval_sec` without a restart.

## File format

Same as `intel.yaml`:

```yaml
items:
  - id: "feedA-ip-1.2.3.4"   # stable, unique id (used for dedup/override)
    type: "ip"               # ip | cidr | domain | url | hash
    value: "1.2.3.4"
    category: "c2"
    severity: "high"
    source: "feedA"
    enabled: true
    expire_at: 0             # optional unix seconds; 0 = never
```

## Rules

- Files are merged by `id`. Across files, the one whose **filename sorts later**
  wins; use numeric prefixes (`10-base.yaml`, `20-override.yaml`) for explicit
  ordering. The **primary `intel.yaml` always wins** over overlay files.
- These files are **read-only** to the node: API / CLI / Hub-sync writes go to
  the primary `intel.yaml`, never here. To change or remove an overlay IOC, edit
  or delete its file here.
- A malformed file fails the whole load (and is skipped on hot-reload, keeping
  the previous set), so a bad drop-in never silently shrinks your IOCs.

See `example-feed.yaml.sample` for a template (rename to `*.yaml` to activate).
