
from .schema import VulnerabilitySchema, validate_finding, normalize_severity, assert_valid_results
from .deduplicator import normalize_vulnerability_name, merge_vulnerabilities, deduplicate_scan_results
from .comparator import compare_with_previous, add_comparison_to_results, print_comparison_summary
from .report_generator import generate_html_report, save_html_report
from .llm_duplicate_resolver import LLMDuplicateConfig, LLMDuplicateResolver, findings_share_same_target
from .unified_vuln_db import UnifiedVulnerabilityDatabase

__all__ = [
    'VulnerabilitySchema', 'validate_finding', 'normalize_severity', 'assert_valid_results',
    'normalize_vulnerability_name', 'merge_vulnerabilities', 'deduplicate_scan_results',
    'compare_with_previous', 'add_comparison_to_results', 'print_comparison_summary',
    'generate_html_report', 'save_html_report',
    'LLMDuplicateConfig', 'LLMDuplicateResolver', 'findings_share_same_target',
    'UnifiedVulnerabilityDatabase',
]
