# AGENTS.md

Guidance for agents (and humans) making commits to
**aws-iot-securetunneling-localproxy**. This repo is a C++14 / CMake project
(not a Brazil package); it uses Boost.Asio/Beast, protobuf and OpenSSL, and a
Nix flake provides the formatter. See `CONTRIBUTING.md` for the project's
overall contribution policy (issues, PRs, CLA).

---

## TL;DR commit checklist

Before every commit:

1. Make one focused, logical change.
2. Update the unit tests and UATs the change affects (see below).
3. `nix fmt` — format the tree (must end clean / idempotent).
4. Run the spelling check (see Spelling); add legitimate technical terms to
   `misc/dictionary.txt` if flagged.
5. Build and run the unit tests (see below); ensure they pass.
6. Stage only the files for this change; write a clear message (see below).
7. Never commit to `main`; never force-push a shared branch without
   coordinating.

---

## Branching

- Work on a feature branch named `dev/<short-kebab-name>` (e.g.
  `dev/security-audit-findings`).
- Per `CONTRIBUTING.md`, work against the latest `main` and keep a change
  focused on one thing — don't reformat unrelated code.
- History may be reworded/rebased **only while the branch has not been pushed**.
  Once shared, prefer new commits; rewriting then requires a coordinated
  force-push.

## One change per commit

- Each commit should be a single, self-contained change (one fix / one feature).
  Don't mix unrelated changes.
- Keep the **tests** and **docs** for a change in the same commit as the change
  (e.g. URL-parsing tests live with the URL-parsing fix).
- With each feature or fix, update the **unit tests** (`test/`, Catch2) and the
  **UATs** (`uat/`) as needed so behavior stays covered: add cases for new
  behavior and adjust existing ones instead of deleting them.
- Keep **formatting** in the same commit as the code it applies to. Normally
  this is automatic: just run `nix fmt` _before_ committing. (Redistributing
  formatting across already-made commits is only needed if it was applied after
  the fact — not part of the normal flow.)

## Commit message style

Match the existing history: a short, imperative, capitalized subject with **no
trailing period**, under ~70 characters.

```
<Imperative subject, e.g. "Fix double callback and buffer leak in WebProxyAdapter">

<One-line statement of the problem / context.>

- Short bullet per distinct point: the reason (why) and the idea (how).

Tests: <one line, if tests were added/changed>
Docs:  <one line, if docs were added/changed>
```

- Subject says _what_ changes; body says _why_ and _the idea_. Keep it terse.
- Use bullets for multiple points; a single `Fix:` line is fine for simple
  changes.
- Reference symbols/files in `code font` where it aids clarity.

Examples from history:

- `Add AF_UNIX support for destination (-d) mode`
- `Fix editor-config errors`

## Build & test

The project builds with CMake + make (see `docs/BUILD.md` for the full guide).
From the repo root:

```bash
mkdir -p build && cd build
cmake ../ -DBUILD_TESTS=ON        # add -DLINK_STATIC_OPENSSL=OFF for dynamic OpenSSL
make -j"$(nproc)"
```

- The proxy binary is produced at `build/bin/localproxy`.
- With `-DBUILD_TESTS=ON`, the Catch2 test binary is `build/bin/localproxytest`;
  run it to execute the unit suite. Ensure all tests pass before committing.
  `ctest --test-dir build` runs the same binary; CI invokes the path directly.
- Build directories matching `*build*/` are git-ignored.
- The end-to-end UATs live in `uat/` (see `uat/README.md`); run the relevant
  scripts when a change affects tunnel/proxy behavior, and keep them current
  with the feature.

Boost, Protobuf and Catch2 are resolved from the system when present and
otherwise built from the versions pinned in `fc_deps.json` — that file is the
**only** place to bump a dependency version. When you do bump one, also refresh
`.github/docker-images/oss-compliance/build-from-source-packages/build-from-source-package-licenses.txt`
and `THIRD_PARTY_LICENSES`, or the license manifests silently go stale. OpenSSL
and zlib always come from the platform and are deliberately absent from the
manifest.

Relevant CMake options (top of `CMakeLists.txt`; full table in `docs/BUILD.md`):

- `BUILD_TESTS` (default OFF) — build the Catch2 unit tests under `test/`.
- `LINK_STATIC_OPENSSL` (default ON) — statically link OpenSSL.
- `GIT_VERSION` (default ON) — derive the version from git history.
- `DISABLE_SSL_HOST_VERIFY_OPT` (default OFF) — production builds may drop the
  `--no-ssl-host-verify` option.
- `LOCALPROXY_DEP_MODE` (default `auto`) — `auto`, `system` or `fetch`.
- `LOCALPROXY_{BOOST,PROTOBUF,CATCH2}_SOURCE` — per-dependency override.
- `LOCALPROXY_LINK_ATOMIC` (default `auto`) — probe for, or force, `-latomic`.

## Formatting & config

- Format with `nix fmt` before committing (treefmt via `flake.nix`: clang-format
  for C/C++ using `.clang-format`, cmake-format for `CMakeLists.txt`,
  `CMakeLists.txt.versioning` and `cmake/*.cmake` using `.cmake-format.json`,
  prettier for Markdown using `prettierrc.yml`). A clean tree after `nix fmt`
  (no diff) is required; don't hand-format against the style.
- If you add a CMake function, register its signature under
  `parse.additional_commands` in `.cmake-format.json`, otherwise cmake-format
  reflows every call site one argument per line.
- If `nix` is not found, install Lix:
  ```bash
  curl -sSf -L https://install.lix.systems/lix | sh -s -- install
  ```
- The repo also ships `.clang-tidy` and `.cmake-format.json`; honor them if you
  run those tools. There are no committed wrapper scripts — run any such tools
  directly.

## Spelling

- A cspell spelling check runs in CI and can be run via the flake:
  ```bash
  nix build -L .#checks.<system>.spelling   # e.g. x86_64-linux, aarch64-linux
  ```
- It scans code, comments, and docs. If it flags a legitimate technical term
  (tool name, CLI flag, identifier), add it to the allowlist
  `misc/dictionary.txt` (kept sorted; cspell matches case-insensitively) rather
  than rewording the term. Don't allowlist genuine misspellings — fix those
  instead.

## Code conventions / gotchas

- C++14. Preserve existing comments and `BOOST_LOG_SEV` logging statements.
- Keep comments concise and logical: explain the _why_ (non-obvious intent,
  invariants, lifetime/ownership, gotchas), not the obvious _what_. Prefer a
  short comment over a verbose block, and don't restate the code.
- Prefer RAII (`shared_ptr`/`unique_ptr`, `lock_guard`) over raw `new`/`delete`
  and manual unlocking.
- **Boost.Asio handler lifetime:** async completion handlers must outlive the
  call that posts them. For self-re-arming handlers use a
  `shared_ptr<std::function>` captured by value and break the resulting
  self-cycle on terminal paths; or capture a `weak_ptr` when another owner (e.g.
  a retry timer) already holds a strong ref for the duration of the call. Note
  that leak detectors generally cannot see `shared_ptr` reference cycles —
  reason about those by hand.
- Validate external input: range-check ports to `[0, 65535]`, handle
  `std::out_of_range` from `stoi`, and reject malformed URLs.
- Security: the proxy negotiates TLS 1.2+ only (SSLv2/3 and TLS 1.0/1.1 are
  disabled in the SSL context).

## Do / don't

- DO keep commits small, buildable, and individually reviewable.
- DO run `nix fmt`, the spelling check, build, and unit tests/UATs before
  committing.
- DON'T weaken or delete tests to make a build pass — fix the code.
- DON'T commit to `main` or force-push shared branches without coordination.
- DON'T strip comments/logging or expand a commit's scope beyond its stated fix.
