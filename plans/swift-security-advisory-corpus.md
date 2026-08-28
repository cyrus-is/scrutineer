---
title: Swift security advisory corpus
status: accepted
date: 2026-08-28
summary: Mine reviewed GitHub advisories and feed verified Swift fix patterns into iOS review skills.
---

# Context

Scrutineer's iOS guidance is hand-written and currently has no traceable connection to
real vulnerability fixes. The GitHub Advisory Database exposes affected package
ecosystems and version ranges, but it does not identify iOS as a runtime platform and
many advisories do not link their fixing commit.

# Plan

1. Start with non-withdrawn, GitHub-reviewed `SwiftURL` advisories with a `fixed`
   range event. Supplement that population with GitHub-reviewed advisories that
   explicitly identify iOS and whose fixing diff changes a native iOS Swift target;
   this catches mixed-language monorepos published under ecosystems such as npm.
2. Preserve every source record in a generated manifest with its advisory-database
   revision, affected package, fixed versions, references, and an auditable disposition:
   promoted evidence, linked but not promoted, cross-repository reference only, or
   unresolved fix link.
3. Require an inspected fixing diff that changes Swift code before distilling a runtime
   pattern. Record iOS applicability separately from the Swift package ecosystem.
4. Store the distilled patterns in a standalone, versioned YAML file. Project the same
   source pattern into security-review and peer-review guidance so security, reliability,
   and correctness fixes reach the appropriate tool.
5. Improve platform detection so Swift is not automatically equated with iOS and so
   root-level Xcode/Swift projects are detected consistently.
6. Validate corpus shape, provenance, IDs, enum values, projection, detection, and wheel
   contents with deterministic offline tests.

# Inclusion rule

A runtime pattern is included only when all of the following are true:

- the advisory is in the bounded source population above, or is an explicit iOS
  advisory whose fix changes a native Swift app target;
- the fixing diff is attributable to the affected repository;
- at least one fixing hunk changes Swift code;
- the vulnerable-to-fixed transformation generalizes into a reviewable code pattern;
- iOS applicability is evidenced by an iOS app target or documented iOS support.

Records that fail a rule remain in the manifest with the reason. Missing upstream fix
links remain `unresolved`; they are not silently treated as clean or converted into
speculative patterns.

# Alternatives considered

- **Treat every Swift package as iOS.** Rejected because Swift is also used for server
  and macOS-only software, producing noisy iOS guidance.
- **Keyword-filter advisory prose.** Rejected as the primary rule because terms such as
  "Swift" also identify unrelated products, while iOS code can live in a non-Swift
  package monorepo.
- **Commit third-party patches.** Rejected to avoid package size and licensing ambiguity.
  The manifest retains immutable source URLs and hashes; the refresh tool downloads
  patches into a local ignored cache.
- **Copy patterns directly into both guidance files.** Rejected because duplicated
  patterns and provenance would drift.

# Backout

Remove the companion pattern file and its loader/projection calls. The existing guidance
YAMLs remain valid and the generators fall back to their current platform checklists.
