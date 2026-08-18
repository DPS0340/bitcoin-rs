---
title: Native benchmark custody binds program and input identity through inherited descriptors
date: 2026-08-12
category: docs/solutions/architecture-patterns
module: native benchmark campaign runner
problem_type: architecture_pattern
component: benchmark_campaign
severity: high
applies_when:
  - "Running a native benchmark campaign where program and input identity must remain stable"
  - "Comparing candidate and reference binaries through child processes"
  - "Persisting benchmark evidence for later independent validation"
related_components:
  - consensus-validation
  - performance-measurement
tags:
  - benchmark-custody
  - file-descriptors
  - proc-self-fd
  - cpu-affinity
  - evidence-integrity
---

# Native benchmark custody binds program and input identity through inherited descriptors

## Context

The benchmark campaign runs candidate and Bitcoin Core processes against the same corpus. A path and a recorded SHA-256 digest do not prove which file a child opened. Another process can replace the path after the runner checks it but before the child opens it. A PATH-resolved launcher adds the same gap for the executable.

The runner also needs a strict wall-time boundary. Proof generation, evidence parsing, and durability checks must not become part of the candidate or Core measurement.

## Guidance

1. **Open identity-bearing files once and retain the descriptors.** Open the corpus, manifest, proof, and custody executable before timing. Hash through a duplicate descriptor. Record the device, inode, mode, size, modification time, and change time. Keep the original descriptor open until the cell ends.

2. **Make the child consume the retained objects.** Pass only the required descriptors with `pass_fds`. Use `/proc/self/fd/N` for the executable and file arguments. Continue to check the configured path as well as the retained descriptor. A path substitution cannot change the object already held open, while an in-place mutation changes the fingerprint and invalidates the arm.

3. **Give each program role one stable descriptor.** Copy each configured program into its run custody directory, verify the copy against the configured digest, and reopen that exact inode read-only. Every candidate arm must use one candidate descriptor. Every Core arm must use one different Core descriptor. Input and executable descriptors must not overlap.

4. **Let the child inherit CPU affinity without a launcher or `preexec_fn`.** Save the caller thread's affinity. Set the campaign affinity, then read it back and require an exact match before `Popen`. Linux can accept a mask and silently remove offline or cpuset-disallowed CPUs. Keep this check inside the `try` that restores the caller in `finally`. The child inherits only the verified mask. This removes PATH launcher substitution and avoids Python's unsafe post-fork `preexec_fn` path. Restore the mask when setup or spawning fails. If restoration fails after the child starts, terminate and reap the child.

5. **Keep the timed interval narrow.** Start wall timing immediately before `Popen`. End it when `wait4` reports the child exit. Verify descriptor fingerprints, flush logs, parse native evidence, and recompute correctness after that endpoint. Generate the cell proof before the first arm.

6. **Bind persisted evidence to its run.** After each child exits, open its native evidence once, record the fingerprint, and parse it through `/proc/self/fd/N`. Retain that descriptor through `custody-result.json` publication. Verify the descriptor and configured path before and after publication, then close the descriptor in the cell cleanup path. A successful arm must include its process identity, wall time, CPU times, and peak RSS. If one arm proves a correctness failure, retain that failure when the other arm has no result. Later validation must require the exact `output_root/<run>/custody-result.json` location, load the same cell configuration and proof, reconstruct every command, reparse native evidence, rederive the verdict, and verify the input paths and retained descriptors again after the last evidence read.

7. **Close descriptors on every path.** Close partial input snapshots, close a prepared candidate if Core preparation raises, close all run descriptors in `finally`, and close temporary executable snapshots during repeated result validation. A descriptor leak makes a long campaign fail with `EMFILE` after apparently valid earlier cells.

8. **State the limit.** Custody proves internal consistency between the configured objects, recorded commands, native evidence, and derived verdict. It is not a cryptographic signature and does not protect against a hostile kernel or a coordinated rewrite of every unsigned artifact.

## Why This Matters

A benchmark ratio is useless when the two programs might have consumed different bytes or run under different CPU masks. Descriptor custody binds the timed children to the objects the runner verified. The separate proof and parsing phases keep bookkeeping out of the wall measurement. Location binding stops a copied result from being presented as another campaign run.

## When to Apply

- A child process receives benchmark inputs through filesystem paths.
- Program identity is part of the benchmark claim.
- CPU affinity must apply to the child but must not leak into the runner.
- A persisted result must be revalidated after the original descriptors are closed.

## Examples

Reject a check-then-reopen sequence:

```python
if sha256(path.read_bytes()) == expected:
    subprocess.Popen([program, "--blocks-file", str(path)])
```

Retain the verified object and pass it to the child:

```python
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
with os.fdopen(os.dup(descriptor), "rb") as stream:
    observed = hashlib.file_digest(stream, "sha256").hexdigest()
program_descriptor = os.open(program_copy, os.O_RDONLY | os.O_CLOEXEC)
program_descriptor_path = f"/proc/self/fd/{program_descriptor}"


process = subprocess.Popen(
    [program_descriptor_path, "--blocks-file", f"/proc/self/fd/{descriptor}"],
    close_fds=True,
    pass_fds=(descriptor, program_descriptor),
)
```

Do not use a PATH launcher or a post-fork callback for affinity:

```python
previous = os.sched_getaffinity(0)
os.sched_setaffinity(0, campaign_affinity)
try:
    process = subprocess.Popen(command, pass_fds=descriptors)
finally:
    os.sched_setaffinity(0, previous)
```

## Related

- [Criterion bench trust](../best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md)
- [Checksig census and the script-check floor](../performance/checksig-census-and-the-script-check-floor.md)
- [Allocator parity changes wall, not CPU](../performance/allocator-parity-changes-wall-not-cpu.md)
