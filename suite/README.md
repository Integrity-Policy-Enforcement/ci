# Guest suite layout

| Location | Responsibility |
|---|---|
| `cases/` | Concrete test inputs, policies and expected results. Each group supplies batches; the verity packages keep their shared setup, scopes and explicit case order. |
| `operations/` | One module per tested operation/path. Its Case factories, triggers, checks and operation-specific resource scopes live together. |
| `resources/` | Shared guest resources: files, mounts, module loading, keyrings and capabilities. These helpers do not define test cases. |
| `model.py`, `runner.py`, `runtime.py`, `scope.py` | Common case model, child-process execution, TAP reporting and state restoration. |
| `ipe.py`, `steps.py`, `triggers.py`, `checks.py` | IPE securityfs access, case setup/read-write steps and common assertions. |
| `assets.py` | Named policy assets. Build/guest paths and hash lists come from the staged `layout` and `hashes` modules. |
| `command.py`, `nodeio.py` | Command execution and raw node I/O. |

For example, `cases/dmverity/kexec_image.py` declares which kernel file and policy
to use and what result is expected. `operations/kexec.py` constructs that Case,
invokes the syscall, checks the staged state and owns kexec-slot cleanup. The
runner does not dispatch on an operation name or know those details.

Shared resource scopes stay in `resources/`; operation-owned scopes stay beside
the operation, such as kexec's image slot and memfd's temporary hugepage pool.
`cases/memfd_controls.py` contains the concrete baseline controls, not another
copy of the memfd implementation.

Imports and case order are explicit. There is no plugin discovery or generated
runtime registry. Keep errno, program exit status and resulting state separate;
process exit releases process-local memory, not global kernel resources.
