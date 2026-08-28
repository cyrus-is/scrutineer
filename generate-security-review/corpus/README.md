# Swift advisory evidence manifest

`swift_advisory_manifest.json` is generated from a pinned checkout of
[`github/advisory-database`](https://github.com/github/advisory-database), whose advisory data is
licensed CC-BY-4.0. It inventories:

- every active, GitHub-reviewed `SwiftURL` advisory with a fixed-version event; and
- reviewed advisories from other ecosystems only after the fixing diff is verified to change
  production Swift in a native iOS target.

This is a candidate inventory, not a claim that every Swift package is an iOS app. GitHub's OSV
schema has no runtime-platform field. An iOS keyword alone is not an inclusion rule.
`swift_security_patterns.yaml` promotes only fixes whose production diff was inspected and whose
iOS/Apple applicability was verified.

Regenerate from a local advisory-database checkout:

```bash
python tools/build_swift_advisory_manifest.py /path/to/advisory-database \
  --output generate-security-review/corpus/swift_advisory_manifest.json \
  --fetch-patches /tmp/scrutineer-swift-fix-patches
```

The optional patch cache is deliberately outside the repository: source patches retain their
upstream project licenses. The manifest records immutable URLs and SHA-256 digests. A refresh must
finish with zero download failures and zero promoted-pattern hash mismatches before its snapshot
revision is accepted.
