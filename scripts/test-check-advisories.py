import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("check_advisories", Path(__file__).with_name("check-advisories.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.lockfile = Path(self.directory.name) / "Cargo.lock"
        self.lockfile.write_text('''[[package]]
name = "quotio"
version = "0.1.0"
[[package]]
name = "time"
version = "0.3.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
''')

    def run_response(self, response):
        with patch.object(module.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(response).encode())) as opener:
            with patch("sys.stdout", new_callable=io.StringIO):
                result = module.check(self.lockfile)
            request = opener.call_args.args[0]
            payload = json.loads(request.data)
            self.assertEqual(payload["queries"], [{"package": {"ecosystem": "crates.io", "name": "time"}, "version": "0.3.47"}])
            return result

    def test_clean_and_vulnerable_results(self):
        self.assertEqual(self.run_response({"results": [{}]}), [])
        findings = self.run_response({"results": [{"vulns": [{"id": "RUSTSEC-example"}]}]})
        self.assertEqual(findings[0]["advisories"], ["RUSTSEC-example"])

    def test_incomplete_or_invalid_responses_fail_closed(self):
        for response in [{"results": []}, {"results": [None]}, {"results": [{"vulns": "bad"}]}]:
            with self.assertRaises((ValueError, AttributeError)):
                self.run_response(response)

    def test_private_registry_metadata_is_not_sent(self):
        self.lockfile.write_text(self.lockfile.read_text().replace("https://github.com/rust-lang/crates.io-index", "https://private.example.invalid/index"))
        with patch.object(module.urllib.request, "urlopen") as opener:
            with self.assertRaises(ValueError):
                module.check(self.lockfile)
            opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
