import json
import xml.etree.ElementTree as ET
from pathlib import Path

from orchestrator import ScannerOrchestrator
from scanners.base import BaseScanner


class StructuredRawScanner(BaseScanner):
    def __init__(self):
        super().__init__("structured")
        self.scan_calls = 0

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        self.scan_calls += 1
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-13T00:00:00Z",
            "command": "structured-scan",
            "raw_output": {
                "summary": {"total": 1},
                "meta": {"flag": True, "optional": None},
                "items": [{"id": "item-1", "score": 7.5}],
                "message": "A&B <critical>",
            },
            "stderr": "",
            "exit_code": 0,
            "findings": [{"id": "raw-finding"}],
        }

    def normalize(self, raw_results):
        return [
            {
                "vulnerability_name": "Structured Finding",
                "severity": "low",
                "asset_id": raw_results["target"],
                "description": "Structured artifact test finding.",
                "remediation": "Fix it.",
                "meta": {
                    "scanner": self.name,
                    "timestamp": raw_results["timestamp"],
                    "host": "example.com",
                    "scheme": "https",
                    "path": "",
                    "port": 443,
                },
            }
        ]


class NativeXmlScanner(BaseScanner):
    def __init__(self, xml_text: str, name: str = "native-xml"):
        super().__init__(name)
        self._xml_text = xml_text

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-13T00:00:00Z",
            "command": "native-xml-scan",
            "raw_output": self._xml_text,
            "stderr": "",
            "exit_code": 0,
            "findings": [],
        }

    def normalize(self, raw_results):
        return []


class ExistingReportScanner(BaseScanner):
    def __init__(self, report_path):
        super().__init__("existing-report")
        self.report_path = report_path

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        report_payload = {
            "report": "ok",
            "entries": [{"name": "entry-1"}],
        }
        self.report_path.write_text(json.dumps(report_payload), encoding="utf-8")
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-13T00:00:00Z",
            "command": "existing-report-scan",
            "raw_output": report_payload,
            "raw_output_path": str(self.report_path),
            "stderr": "",
            "exit_code": 0,
            "findings": [],
        }

    def normalize(self, raw_results):
        return []


class ZapJsonAndXmlScanner(BaseScanner):
    def __init__(self, raw_dir: Path):
        super().__init__("zap")
        self.raw_dir = raw_dir

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.raw_dir / "zap_example.json"
        xml_path = self.raw_dir / "zap_example.xml"
        json_path.write_text('{"site":[]}\n', encoding="utf-8")
        xml_path.write_text("<OWASPZAPReport></OWASPZAPReport>\n", encoding="utf-8")
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-13T00:00:00Z",
            "command": "zap",
            "raw_output": {"site": []},
            "raw_output_path": str(json_path),
            "defectdojo_raw_artifact": {
                "path": str(xml_path),
                "artifact_format": "xml",
                "native": True,
                "role": "defectdojo-native-parser-input",
                "source": "zap-traditional-xml-report",
            },
            "stderr": "",
            "exit_code": 0,
            "findings": [],
        }

    def normalize(self, raw_results):
        return []


class WapitiJsonAndXmlScanner(BaseScanner):
    def __init__(self, raw_dir: Path, *, expose_xml: bool = True):
        super().__init__("wapiti")
        self.raw_dir = raw_dir
        self.expose_xml = expose_xml

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.raw_dir / "wapiti_example.json"
        xml_path = self.raw_dir / "wapiti_example.xml"
        json_path.write_text('{"vulnerabilities":{}}\n', encoding="utf-8")
        xml_path.write_text("<report type=\"security\"></report>\n", encoding="utf-8")
        result = {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-13T00:00:00Z",
            "command": "wapiti",
            "raw_output": {"vulnerabilities": {}},
            "raw_output_path": str(json_path),
            "stderr": "",
            "exit_code": 0,
            "findings": [],
        }
        if self.expose_xml:
            result["defectdojo_raw_artifact"] = {
                "path": str(xml_path),
                "artifact_format": "xml",
                "native": True,
                "safe_importable": True,
                "role": "defectdojo-native-parser-input",
                "source": "wapiti-xml-report",
            }
        return result

    def normalize(self, raw_results):
        return []


class SkipOnlyWebScanner(BaseScanner):
    def __init__(self):
        super().__init__("skip-only")
        self.scanner_type = "web"
        self.was_called = False

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        self.was_called = True
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-13T00:00:00Z",
            "findings": [],
        }

    def normalize(self, raw_results):
        return []


def _raw_artifact_pair(orchestrator: ScannerOrchestrator):
    if orchestrator.current_run_folder is not None:
        raw_dir = orchestrator.current_run_folder / "raw"
    else:
        raw_dir = (
            orchestrator.reports_dir.parent / "data"
            if orchestrator.reports_dir.parent
            else Path("data")
        )
    json_files = sorted(raw_dir.glob("*.json"))
    xml_files = sorted(raw_dir.glob("*.xml"))
    assert len(json_files) == 1
    assert len(xml_files) == 1
    return json_files[0], xml_files[0]


def test_structured_result_saves_matching_json_and_generated_xml(tmp_path):
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    scanner = StructuredRawScanner()
    orchestrator.register_scanner(scanner.name, scanner)

    result = orchestrator.run_scanner(scanner.name, "https://example.com", save_raw=True)
    expected_findings = [
        {
            "vulnerability_name": "Structured Finding",
            "severity": "low",
            "asset_id": "https://example.com",
            "description": "Structured artifact test finding.",
            "remediation": "Fix it.",
            "meta": {
                "scanner": scanner.name,
                "timestamp": "2026-04-13T00:00:00Z",
                "host": "example.com",
                "scheme": "https",
                "path": "",
                "port": 443,
            },
        }
    ]

    json_path, xml_path = _raw_artifact_pair(orchestrator)
    raw_payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert raw_payload["raw_output"]["summary"]["total"] == 1

    xml_root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    assert xml_root.tag == "scanner_result"
    assert xml_root.findtext("./scanner") == scanner.name
    assert xml_root.findtext("./raw_output/summary/total") == "1"
    assert xml_root.findtext("./raw_output/meta/flag") == "true"
    assert xml_root.find("./raw_output/meta/optional").attrib["type"] == "null"
    assert xml_root.findtext("./raw_output/items/item/id") == "item-1"
    assert xml_root.findtext("./raw_output/message") == "A&B <critical>"

    assert result["findings"] == expected_findings
    assert result["raw_findings_count"] == 1
    assert result["normalized_findings_count"] == 1


def test_native_xml_is_preserved_as_is_for_xml_artifact(tmp_path):
    xml_text = "<?xml version=\"1.0\"?><nmaprun><host addr=\"example.com\" /></nmaprun>"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    scanner = NativeXmlScanner(xml_text)
    orchestrator.register_scanner(scanner.name, scanner)

    orchestrator.run_scanner(scanner.name, "example.com", save_raw=True)

    json_path, xml_path = _raw_artifact_pair(orchestrator)
    assert json.loads(json_path.read_text(encoding="utf-8"))["raw_output"] == xml_text
    assert xml_path.read_text(encoding="utf-8") == xml_text


def test_nmap_native_xml_is_marked_as_defectdojo_raw_input(tmp_path):
    xml_text = "<?xml version=\"1.0\"?><nmaprun><host addr=\"example.com\" /></nmaprun>"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    scanner = NativeXmlScanner(xml_text, name="nmap")
    orchestrator.register_scanner(scanner.name, scanner)

    result = orchestrator.run_scanner(scanner.name, "example.com", save_raw=True)

    raw_artifact = result["defectdojo_raw_artifact"]
    assert raw_artifact["artifact_format"] == "xml"
    assert raw_artifact["native"] is True
    assert raw_artifact["role"] == "defectdojo-native-parser-input"
    assert Path(raw_artifact["path"]).read_text(encoding="utf-8") == xml_text


def test_aggregate_results_include_defectdojo_raw_upload_manifest(tmp_path):
    xml_text = "<?xml version=\"1.0\"?><nmaprun><host addr=\"example.com\" /></nmaprun>"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    scanner = NativeXmlScanner(xml_text, name="nmap")
    orchestrator.register_scanner(scanner.name, scanner)

    results = orchestrator.run_all("example.com", save_raw=True)

    manifest = results["defectdojo_raw_uploads"]
    assert len(manifest) == 1
    assert manifest[0]["scanner"] == "nmap"
    assert manifest[0]["execution_key"] == "nmap"
    assert manifest[0]["scan_type"] == "Nmap Scan"
    assert manifest[0]["safe_importable"] is True
    assert manifest[0]["test_title"] == "nmap | example.com"
    assert Path(manifest[0]["raw_artifact_path"]).read_text(encoding="utf-8") == xml_text
    assert any(
        artifact["artifact_format"] == "xml" and artifact["native"] is True
        for artifact in manifest[0]["raw_artifacts"]
    )


def test_zap_manifest_uses_scanner_xml_report_for_defectdojo(tmp_path):
    raw_dir = tmp_path / "zap-raw"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path / "reports")
    scanner = ZapJsonAndXmlScanner(raw_dir)
    orchestrator.register_scanner(scanner.name, scanner)

    results = orchestrator.run_all("example.com", save_raw=True)

    manifest_entry = results["defectdojo_raw_uploads"][0]
    assert manifest_entry["scanner"] == "zap"
    assert manifest_entry["scan_type"] == "ZAP Scan"
    assert manifest_entry["artifact_format"] == "xml"
    assert manifest_entry["native"] is True
    assert manifest_entry["safe_importable"] is True
    assert manifest_entry["artifact_role"] == "defectdojo-native-parser-input"
    assert Path(manifest_entry["raw_artifact_path"]).name == "zap_example.xml"
    assert Path(manifest_entry["raw_artifact_path"]).read_text(encoding="utf-8").startswith("<OWASPZAPReport")


def test_wapiti_manifest_uses_scanner_xml_report_for_defectdojo(tmp_path):
    raw_dir = tmp_path / "wapiti-raw"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path / "reports")
    scanner = WapitiJsonAndXmlScanner(raw_dir)
    orchestrator.register_scanner(scanner.name, scanner)

    results = orchestrator.run_all("example.com", save_raw=True)

    manifest_entry = results["defectdojo_raw_uploads"][0]
    assert manifest_entry["scanner"] == "wapiti"
    assert manifest_entry["scan_type"] == "Wapiti Scan"
    assert manifest_entry["artifact_format"] == "xml"
    assert manifest_entry["native"] is True
    assert manifest_entry["safe_importable"] is True
    assert manifest_entry["role"] == "defectdojo-native-parser-input"
    assert manifest_entry["artifact_role"] == "defectdojo-native-parser-input"
    assert Path(manifest_entry["raw_artifact_path"]).name == "wapiti_example.xml"
    assert Path(manifest_entry["raw_artifact_path"]).read_text(encoding="utf-8").startswith("<report")


def test_wapiti_json_only_result_does_not_promote_json_as_default_defectdojo_artifact(tmp_path):
    raw_dir = tmp_path / "wapiti-raw"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path / "reports")
    scanner = WapitiJsonAndXmlScanner(raw_dir, expose_xml=False)
    orchestrator.register_scanner(scanner.name, scanner)

    results = orchestrator.run_all("example.com", save_raw=True)

    result = results["scanner_instances"]["wapiti"]
    manifest_entry = results["defectdojo_raw_uploads"][0]
    assert result["scanner"] == "wapiti"
    assert manifest_entry["scanner"] == "wapiti"
    assert manifest_entry["raw_artifact_path"] is None
    assert manifest_entry["safe_importable"] is False
    assert any(
        artifact["artifact_format"] == "json" and artifact["native"] is True
        for artifact in manifest_entry["raw_artifacts"]
    )


def test_project_generated_xml_wrapper_is_not_defectdojo_native_input(tmp_path):
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    scanner = StructuredRawScanner()
    orchestrator.register_scanner(scanner.name, scanner)

    result = orchestrator.run_scanner(scanner.name, "https://example.com", save_raw=True)

    xml_artifacts = [
        artifact
        for artifact in result["raw_artifacts"]
        if artifact["artifact_format"] == "xml"
    ]
    assert xml_artifacts
    assert xml_artifacts[0]["role"] == "project-generated-xml-wrapper"
    assert xml_artifacts[0]["native"] is False
    assert "defectdojo_raw_artifact" not in result


def test_existing_raw_report_path_gets_xml_sidecar_without_extra_json_copy(tmp_path):
    report_path = tmp_path / "existing-report.json"
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path / "reports")
    scanner = ExistingReportScanner(report_path)
    orchestrator.register_scanner(scanner.name, scanner)

    orchestrator.run_scanner(scanner.name, "example.com", save_raw=True)

    xml_path = report_path.with_suffix(".xml")
    assert report_path.exists()
    assert xml_path.exists()
    xml_root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    assert xml_root.findtext("./raw_output/report") == "ok"
    assert xml_root.findtext("./raw_output_path") == str(report_path)
    assert not list((orchestrator.current_run_folder / "raw").glob("existing-report_*.json"))


def test_skipped_scanner_result_also_saves_json_and_xml_when_raw_save_is_enabled(monkeypatch, tmp_path):
    def fake_probe(target: str, timeout: int = 8):
        return {
            "input_target": target,
            "normalized_target": "https://example.com",
            "selected_scheme": "https",
            "reachable": True,
            "supports_http2": True,
            "supports_http1_1": False,
            "http2_only": True,
            "transport_detected": "http2_only",
            "detected_http_version": "HTTP/2",
            "probe_method": "fake",
            "reason": "fake probe",
            "attempts": [],
        }

    monkeypatch.setattr("orchestrator.probe_http_transport", fake_probe)

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    scanner = SkipOnlyWebScanner()
    orchestrator.register_scanner(scanner.name, scanner)

    result = orchestrator.run_scanner(scanner.name, "example.com", save_raw=True)

    json_path, xml_path = _raw_artifact_pair(orchestrator)
    assert scanner.was_called is False
    assert orchestrator.current_run_folder is not None
    assert json_path.parent == orchestrator.current_run_folder / "raw"
    assert xml_path.parent == orchestrator.current_run_folder / "raw"
    assert result["scan_route"] == "skipped"
    assert json.loads(json_path.read_text(encoding="utf-8"))["scan_route"] == "skipped"
    xml_root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    assert xml_root.findtext("./scan_route") == "skipped"
    assert "HTTP/2-only" in xml_root.findtext("./error")
