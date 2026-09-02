# AGENTS.md

- Before debugging a recurring issue or designing in an already-touched area,
  check `CONCEPTS.md` for existing domain vocabulary and invariants; otherwise
  work can repeat settled failures or contradict project knowledge.
- Before adding or changing durable project knowledge, reconcile each affected
  project-specific term in `CONCEPTS.md`; otherwise diagnoses and shared
  vocabulary drift independently.
- During benchmark campaigns, retain one canonical corpus and at most one disposable
  run fixture. Before every corpus build, clone, or run, declare its worst-case
  additional disk footprint, reserve threshold, and free-space check cadence; refuse
  to start unless free space covers both the footprint and reserve. During long runs,
  recheck at that cadence and stop the run and delete its disposable fixture if free
  space reaches the reserve. Record compact results and delete the disposable fixture
  before starting the next run, because accumulated benchmark copies have exhausted
  the workstation's home dataset.
- Acceptance criteria belong in the issue or PR that scopes the work, not in
  per-task files that outlive the task. Execution proof belongs in CI output,
  not in tracked artifacts that become permanent without a reviewer. Agent
  scratch is local and gitignored (`.agent-tasks/`); it never enters the
  repository. Prefer simplifying code over adding permanent verification
  scaffolding — a test that asserts a file is absent is itself the kind of
  scaffolding this rule removes.
- For every TLS path, use Rustls with default features disabled and a reviewed
  non-C crypto provider, and keep the native-TLS/C-provider family in `deny.toml`
  complete, because Rustls and adapter feature defaults can reintroduce AWS-LC,
  ring, OpenSSL, or platform TLS transitively.
