"""Offline regression tests for the Swift advisory-derived review corpus."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scrutineer import paths
from scrutineer.review_patterns import (
    PatternValidationError,
    has_ios_swift_evidence,
    ios_swift_component_paths,
    load_swift_patterns,
    merge_peer_patterns,
    merge_security_patterns,
    path_matches,
    service_map_has_ios_swift,
)

PATTERNS = ROOT / "generate-security-review" / "swift_security_patterns.yaml"
SECURITY_GUIDANCE = ROOT / "generate-security-review" / "security_guidance.yaml"
PEER_GUIDANCE = ROOT / "generate-peer-review" / "peer_review_guidance.yaml"
SECURITY_GENERATOR = ROOT / "generate-security-review" / "generate.py"
PEER_GENERATOR = ROOT / "generate-peer-review" / "generate.py"
MANIFEST = ROOT / "generate-security-review" / "corpus" / "swift_advisory_manifest.json"


def write_file(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def indexed_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


class SwiftPatternCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = load_swift_patterns(PATTERNS)

    def test_corpus_shape_and_evidence(self) -> None:
        self.assertEqual(9, len(self.corpus["fixes"]))
        self.assertEqual(10, len(self.corpus["patterns"]))
        self.assertEqual(
            "6e1af5dc39883b8a684f6483b728fd18c5808859",
            self.corpus["source_snapshot"]["advisory_database_commit"],
        )
        pattern_ids = [pattern["id"] for pattern in self.corpus["patterns"]]
        self.assertEqual(len(pattern_ids), len(set(pattern_ids)))

    def test_projection_routes_security_and_reliability_patterns(self) -> None:
        security = yaml.safe_load(SECURITY_GUIDANCE.read_text(encoding="utf-8"))
        peer = yaml.safe_load(PEER_GUIDANCE.read_text(encoding="utf-8"))
        security_added = merge_security_patterns(security, self.corpus)
        peer_added = merge_peer_patterns(peer, self.corpus)

        self.assertEqual(8, security_added)
        self.assertEqual(10, peer_added)
        security_ids = {item["id"] for item in security["mobile"]["ios"]["checklist"]}
        peer_ids = {item["id"] for item in peer["mobile"]["ios"]["preflight_checks"]}
        self.assertNotIn("swift-untrusted-parser-trap", security_ids)
        self.assertIn("swift-untrusted-parser-trap", peer_ids)
        self.assertIn("ios-webview-bridge-exact-trust", security_ids)

    def test_duplicate_projection_is_rejected(self) -> None:
        guidance = yaml.safe_load(SECURITY_GUIDANCE.read_text(encoding="utf-8"))
        merge_security_patterns(guidance, self.corpus)
        with self.assertRaises(PatternValidationError):
            merge_security_patterns(guidance, self.corpus)

    def test_unknown_evidence_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.corpus)
        invalid["patterns"][0]["evidence"] = ["GHSA-xxxx-xxxx-xxxx"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patterns.yaml"
            path.write_text(yaml.safe_dump(invalid, sort_keys=False), encoding="utf-8")
            with self.assertRaises(PatternValidationError):
                load_swift_patterns(path)

    def test_non_swift_production_evidence_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.corpus)
        invalid["fixes"][0]["fix_commits"][0]["production_files"] = [
            "Sources/Crypto/native.c"
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patterns.yaml"
            path.write_text(yaml.safe_dump(invalid, sort_keys=False), encoding="utf-8")
            with self.assertRaises(PatternValidationError):
                load_swift_patterns(path)

    def test_custom_guidance_without_ios_remains_compatible(self) -> None:
        self.assertEqual(0, merge_security_patterns({"backend": {}}, self.corpus))
        self.assertEqual(0, merge_peer_patterns({"backend": {}}, self.corpus))

    def test_snapshot_fix_count_mismatch_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.corpus)
        invalid["source_snapshot"]["included_fix_records"] = 999
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patterns.yaml"
            path.write_text(yaml.safe_dump(invalid, sort_keys=False), encoding="utf-8")
            with self.assertRaises(PatternValidationError):
                load_swift_patterns(path)

    def test_root_glob_semantics(self) -> None:
        self.assertTrue(path_matches("App.swift", "**/*.swift"))
        self.assertTrue(path_matches("Sources/App.swift", "**/*.swift"))
        self.assertTrue(path_matches("project.yml", "**/project.yml"))


class IOSDetectionTests(unittest.TestCase):
    def test_root_swiftui_app_with_iphoneos_project_is_ios(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(
                root, "App.swift", "import SwiftUI\n@main struct DemoApp: App {}\n"
            )
            write_file(
                root,
                "Demo.xcodeproj/project.pbxproj",
                "SDKROOT = iphoneos;\nIPHONEOS_DEPLOYMENT_TARGET = 18.0;\n",
            )
            self.assertTrue(has_ios_swift_evidence(root, indexed_files(root)))

    def test_uikit_import_is_strong_ios_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Sources/ViewController.swift", "import UIKit\n")
            self.assertTrue(has_ios_swift_evidence(root, indexed_files(root)))

    def test_server_swift_is_not_ios(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Package.swift", "import PackageDescription\n")
            write_file(root, "Sources/App/main.swift", "import Vapor\n")
            self.assertFalse(has_ios_swift_evidence(root, indexed_files(root)))

    def test_ios_manifest_without_production_swift_is_not_an_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(
                root,
                "Package.swift",
                "import PackageDescription\nlet package = Package(platforms: [.iOS(.v17)])\n",
            )
            self.assertFalse(has_ios_swift_evidence(root, indexed_files(root)))

    def test_ios_test_fixture_does_not_classify_package_as_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Package.swift", "import PackageDescription\n")
            write_file(root, "Tests/ios/Fixture.swift", "import UIKit\n")
            self.assertFalse(has_ios_swift_evidence(root, indexed_files(root)))

    def test_macos_swiftui_project_is_not_ios(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(
                root, "App.swift", "import SwiftUI\n@main struct MacApp: App {}\n"
            )
            write_file(root, "Mac.xcodeproj/project.pbxproj", "SDKROOT = macosx;\n")
            self.assertFalse(has_ios_swift_evidence(root, indexed_files(root)))

    def test_mixed_swift_monorepo_scopes_ios_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "apps/ios/App.swift", "import SwiftUI\n")
            write_file(root, "services/api/Sources/App/main.swift", "import Vapor\n")
            self.assertEqual(
                ["apps/ios"],
                ios_swift_component_paths(root, indexed_files(root)),
            )

    def test_service_map_can_prove_ios_swift_app(self) -> None:
        self.assertTrue(
            service_map_has_ios_swift(
                {
                    "components": [
                        {
                            "type": "app",
                            "language": "swift",
                            "platform": "ios",
                            "framework": "swiftui",
                        }
                    ]
                }
            )
        )
        self.assertFalse(
            service_map_has_ios_swift(
                {
                    "components": [
                        {
                            "type": "service",
                            "language": "swift",
                            "platform": "linux",
                        }
                    ]
                }
            )
        )

    def test_service_map_evidence_is_scoped_to_local_component_files(self) -> None:
        data = {
            "components": [
                {
                    "type": "app",
                    "language": "swift",
                    "platform": "ios",
                    "framework": "swiftui",
                    "path": "apps/ios",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            swift_file = write_file(root, "apps/ios/App.swift", "import SwiftUI\n")
            self.assertTrue(service_map_has_ios_swift(data, root, [swift_file]))

            remote_only = copy.deepcopy(data)
            remote_only["components"][0]["path"] = "other-repo/ios"
            self.assertFalse(service_map_has_ios_swift(remote_only, root, [swift_file]))


class GeneratorIntegrationTests(unittest.TestCase):
    def run_generator(self, generator: Path, repository: Path, *extra: str) -> str:
        result = subprocess.run(
            [
                sys.executable,
                str(generator),
                str(repository),
                "--dry-run",
                "--no-service-map",
                *extra,
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def ios_fixture(self, root: Path) -> None:
        write_file(root, "App/App.swift", "import SwiftUI\n#if os(iOS)\n#endif\n")
        write_file(
            root,
            "App/App.xcodeproj/project.pbxproj",
            "SDKROOT = iphoneos;\n",
        )

    def test_security_generator_renders_fix_evidence_and_unsafe_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.ios_fixture(root)
            output = self.run_generator(SECURITY_GENERATOR, root)
            self.assertIn(
                "Unchecked Swift buffer length at a native API boundary", output
            )
            self.assertIn("GHSA-9m44-rr2w-ppp7", output)
            self.assertIn("unsafe boundaries remain in scope", output)
            self.assertNotIn("not applicable to Swift", output)

    def test_peer_generator_receives_availability_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.ios_fixture(root)
            output = self.run_generator(PEER_GENERATOR, root)
            self.assertIn("Untrusted parser input reaches a Swift trap", output)
            self.assertIn("GHSA-w8xv-rwgf-4fwh", output)

    def test_server_swift_does_not_receive_ios_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "Package.swift", "import PackageDescription\n")
            write_file(root, "Sources/App/main.swift", "import Vapor\n")
            output = self.run_generator(SECURITY_GENERATOR, root)
            self.assertNotIn("iOS (Swift/SwiftUI) Checklist", output)
            self.assertNotIn(
                "Unchecked Swift buffer length at a native API boundary", output
            )

    def test_mixed_monorepo_renders_only_ios_component_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_file(root, "apps/ios/App.swift", "import SwiftUI\n")
            write_file(root, "services/api/Sources/App/main.swift", "import Vapor\n")
            output = self.run_generator(SECURITY_GENERATOR, root)
            self.assertIn("When reviewing `apps/ios`:", output)
            self.assertNotIn("services/api", output)

    def test_patterns_can_be_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.ios_fixture(root)
            output = self.run_generator(
                SECURITY_GENERATOR,
                root,
                "--no-swift-patterns",
            )
            self.assertIn("iOS (Swift/SwiftUI) Checklist", output)
            self.assertNotIn(
                "Unchecked Swift buffer length at a native API boundary", output
            )


class ManifestAndPackagingTests(unittest.TestCase):
    def test_manifest_covers_snapshot_and_patch_fetch(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(58, manifest["statistics"]["candidateRecords"])
        self.assertEqual(56, manifest["statistics"]["swiftEcosystemRecords"])
        self.assertEqual(
            2,
            manifest["statistics"]["verifiedNativeIosSwiftFixRecords"],
        )
        self.assertEqual(
            9,
            manifest["statistics"]["dispositions"]["promoted-pattern-evidence"],
        )
        self.assertEqual(
            manifest["patchFetch"]["requested"],
            manifest["patchFetch"]["downloaded"],
        )
        self.assertEqual(0, manifest["patchFetch"]["failed"])
        self.assertEqual(0, manifest["patchFetch"]["promotedHashMismatches"])
        results_by_url = {
            result["url"]: result for result in manifest["patchFetch"]["results"]
        }
        for fix in load_swift_patterns(PATTERNS)["fixes"]:
            for commit in fix["fix_commits"]:
                result = results_by_url[commit["url"]]
                self.assertEqual("downloaded", result["status"])
                self.assertEqual(commit["patch_sha256"], result["patchSha256"])
                self.assertTrue(result["hashMatchesCorpus"])
        record_ids = {record["id"] for record in manifest["records"]}
        self.assertNotIn("GHSA-2c7v-qcjp-4mg2", record_ids)
        openclaw = next(
            record
            for record in manifest["records"]
            if record["id"] == "GHSA-4p4f-fc8q-84m3"
        )
        self.assertIn("verified-native-ios-swift-fix", openclaw["selectionBasis"])
        self.assertTrue(openclaw["corpusFix"]["commits"])

    def test_runtime_asset_is_required_and_bundled(self) -> None:
        self.assertEqual(PATTERNS.resolve(), paths.SWIFT_SECURITY_PATTERNS.resolve())
        self.assertNotIn(PATTERNS, paths.missing_assets())
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(
            '"generate-security-review/swift_security_patterns.yaml" = '
            '"scrutineer/_assets/generate-security-review/swift_security_patterns.yaml"',
            pyproject,
        )


if __name__ == "__main__":
    unittest.main()
