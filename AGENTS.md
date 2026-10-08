# Agent Guidelines & Development Rules - PenNoivisor

All AI agents and contributors working on this repository must strictly adhere to the following rules:

---

## 1. Code Comments & Hygiene
- **Comments allowed with care**: Meaningful comments (`//`, `/* ... */`, docstrings) explaining complex low-level interactions, hardware quirks, or non-obvious architecture decisions are permitted.
- **Beware of outdated or dead comments**: Strictly avoid obsolete, inaccurate, or dead comments that drift from the actual implementation. Always update or remove comments when modifying corresponding code.
- **No commented-out code**: Never commit commented-out dead code, temporary debug remnants, TODOs, or FIXMEs.

---

## 2. Technical English for Code and Commits
- **Language**: All source code and version control operations must be written in technical English.
  - Variable names, functions, structs, enums, macros, and symbols.
  - Log strings, error messages, and debug output.
- **Git Commits**: All commit messages must be in concise, imperative technical English (e.g., Conventional Commits format):
  - `feat(vt_core): implement ept violation handler`
  - `fix(svm_core): correct vmexit handling for msr write`
  - `refactor(road): restructure memory mapping logic`

---

## 3. Strict Variable Naming Conventions
- **Rust**: All variables, function parameters, and struct fields must strictly use standard `snake_case` (e.g., `guest_rip`, `exit_reason`, `target_buffer`, `processor_id`, `cr3_value`).
- **C / C++ / C#**: Variables must strictly use `camelCase`.
  - Local variables (e.g., `guestRip`, `exitReason`, `targetBuffer`)
  - Function parameters (e.g., `processorId`, `pageDirectoryBase`, `isNested`)
  - Struct and class fields/members (e.g., `cr3Value`, `eptPointer`, `virtualAddress`)
- Constants and macros may follow standard `UPPER_SNAKE_CASE` where required by system headers or language conventions.

---

## 4. No Markdown Documentation Files in the Repository
- **No generated `.md` files**: Do not generate, add, or commit Markdown (`.md`) documentation files, reports, summaries, or walkthrough notes inside the repository tree.
- **External Markdown location**: Any temporary or generated `.md` files must be created in the system temporary directory; do not persist them in the codebase.

---

## 5. Build and Test Locations
- **Build output root**: All MatrixHV build, packaging, and generated boot artifacts must be written under the repository-root `builds/` directory.
- **Generated artifacts are not versioned**: Files produced under `builds/` must remain ignored by Git unless the user explicitly requests otherwise.
- **Tests**: Source-level and host-runnable tests belong under `tests/`.
- **Temporary compiler output**: Cargo target directories may use temporary locations or `builds/.cargo-target`; do not place compiler caches in source directories.

---

## 7. Rust Best Practices & Idiomatic Code
- **No Dead Code or Dead Imports**: Strictly avoid leaving unused functions, constants, structs, or fields in the codebase. Every item must be actively referenced or promptly removed.
- **No Lint Silencing**: Do NOT use `#[allow(dead_code)]` or `#[allow(unused_imports)]` to suppress compiler warnings or mask incomplete refactoring. Source code must compile warning-free under `--target x86_64-unknown-uefi` without silencing annotations.
- **Minimal, Cohesive Modules**: Avoid premature fragmentation (e.g., creating dedicated files for a few constants or 10-line forwarding wrappers). Keep closely related architectural primitives, state management, and register access cohesive within single modules.
- **Direct & Explicit Imports**: Import types and functions directly from their canonical module rather than constructing artificial re-export shim hierarchies.
- **Prune Unused Abstractions**: Remove speculative traits, redundant DTO wrappers, and unreferenced error variants that add indirection without serving real runtime logic.
