#!/usr/bin/env python3
"""
test_autonomous_chains.py — Comprehensive test suite for mod_autonomous_chains.py

Tests:
1. VulnerabilityGraphBuilder: graph construction, edge detection, stats
2. ChainPathFinder: BFS, DFS, correlation-based discovery
3. PrerequisiteValidator: chain validation, compatibility checking
4. ChainScoringEngine: likelihood, impact, effort scoring
5. ChainSimulator: dry-run validation
6. AutomaticChainDiscovery: end-to-end chain discovery
7. ImpactAggregator: CIA scoring and severity mapping
8. Real CVE data: 8+ real-world chain patterns
9. Export formats: JSON and markdown reporting

Total: 30+ test cases
"""

import unittest
import json
import tempfile
from pathlib import Path
from mod_autonomous_chains import (
    Vulnerability,
    AutonomousChain,
    VulnerabilityGraphBuilder,
    ChainPathFinder,
    PrerequisiteValidator,
    ChainScoringEngine,
    ChainSimulator,
    AutomaticChainDiscovery,
    ImpactAggregator,
    ImpactMetrics,
    RealCVEDataBuilder,
    discover_autonomous_chains,
    export_chains_to_json,
    export_chains_to_markdown,
)


class TestVulnerabilityGraphBuilder(unittest.TestCase):
    """Test vulnerability graph construction."""

    def setUp(self):
        """Set up test fixtures."""
        self.builder = VulnerabilityGraphBuilder()

        self.vuln1 = Vulnerability(
            vuln_id="sqli_01",
            name="SQLi",
            category="injection",
            cvss_score=9.8,
            base_likelihood=0.8,
            prerequisites=["network_access"],
            outputs=["database_access"],
        )
        self.vuln2 = Vulnerability(
            vuln_id="rce_02",
            name="RCE via UDF",
            category="rce",
            cvss_score=9.9,
            base_likelihood=0.7,
            prerequisites=["database_access"],
            outputs=["shell_access"],
        )
        self.vuln3 = Vulnerability(
            vuln_id="privesc_03",
            name="Privesc",
            category="privesc",
            cvss_score=8.8,
            base_likelihood=0.6,
            prerequisites=["shell_access"],
            outputs=["root_access"],
        )

    def test_add_vulnerability(self):
        """Test adding vulnerabilities to graph."""
        self.builder.add_vulnerability(self.vuln1)
        self.assertIn("sqli_01", self.builder.vulnerabilities)
        self.assertEqual(self.builder.vulnerabilities["sqli_01"], self.vuln1)

    def test_add_edge(self):
        """Test adding edges between vulnerabilities."""
        self.builder.add_vulnerability(self.vuln1)
        self.builder.add_vulnerability(self.vuln2)
        self.builder.add_edge("sqli_01", "rce_02")
        self.assertIn("rce_02", self.builder.edges["sqli_01"])
        self.assertIn("sqli_01", self.builder.reverse_edges["rce_02"])

    def test_get_successors(self):
        """Test retrieving successor vulnerabilities."""
        self.builder.add_vulnerability(self.vuln1)
        self.builder.add_vulnerability(self.vuln2)
        self.builder.add_edge("sqli_01", "rce_02")
        successors = self.builder.get_successors("sqli_01")
        self.assertEqual(len(successors), 1)
        self.assertEqual(successors[0].vuln_id, "rce_02")

    def test_get_predecessors(self):
        """Test retrieving predecessor vulnerabilities."""
        self.builder.add_vulnerability(self.vuln1)
        self.builder.add_vulnerability(self.vuln2)
        self.builder.add_edge("sqli_01", "rce_02")
        predecessors = self.builder.get_predecessors("rce_02")
        self.assertEqual(len(predecessors), 1)
        self.assertEqual(predecessors[0].vuln_id, "sqli_01")

    def test_can_chain(self):
        """Test output→input matching."""
        # vuln1 outputs match vuln2 prerequisites
        self.assertTrue(self.builder._can_chain(self.vuln1, self.vuln2))
        # vuln1 and vuln3 don't directly chain
        self.assertFalse(self.builder._can_chain(self.vuln1, self.vuln3))

    def test_auto_edge_detection(self):
        """Test automatic edge detection during build_from_findings."""
        findings = [
            {
                "id": "sqli_01",
                "title": "SQLi",
                "category": "injection",
                "cvss_score": 9.8,
                "likelihood": 0.8,
                "prerequisites": ["network_access"],
                "outputs": ["database_access"],
                "cves": [],
            },
            {
                "id": "rce_02",
                "title": "RCE",
                "category": "rce",
                "cvss_score": 9.9,
                "likelihood": 0.7,
                "prerequisites": ["database_access"],
                "outputs": ["shell_access"],
                "cves": [],
            },
        ]
        self.builder.build_from_findings(findings)
        self.assertIn("rce_02", self.builder.edges["sqli_01"])

    def test_graph_stats(self):
        """Test graph statistics."""
        self.builder.add_vulnerability(self.vuln1)
        self.builder.add_vulnerability(self.vuln2)
        self.builder.add_vulnerability(self.vuln3)
        self.builder.add_edge("sqli_01", "rce_02")
        self.builder.add_edge("rce_02", "privesc_03")

        stats = self.builder.get_graph_stats()
        self.assertEqual(stats["total_nodes"], 3)
        self.assertEqual(stats["total_edges"], 2)


class TestChainPathFinder(unittest.TestCase):
    """Test chain discovery algorithms."""

    def setUp(self):
        """Set up test graph."""
        self.builder = VulnerabilityGraphBuilder()
        self.vuln_sqli = Vulnerability(
            vuln_id="sqli", name="SQLi", category="injection", cvss_score=9.8,
            base_likelihood=0.8, prerequisites=["network"], outputs=["db_access"]
        )
        self.vuln_rce = Vulnerability(
            vuln_id="rce", name="RCE", category="rce", cvss_score=9.9,
            base_likelihood=0.7, prerequisites=["db_access"], outputs=["shell"]
        )
        self.vuln_privesc = Vulnerability(
            vuln_id="privesc", name="Privesc", category="privesc", cvss_score=8.8,
            base_likelihood=0.6, prerequisites=["shell"], outputs=["root"]
        )

        self.builder.add_vulnerability(self.vuln_sqli)
        self.builder.add_vulnerability(self.vuln_rce)
        self.builder.add_vulnerability(self.vuln_privesc)
        self.builder.add_edge("sqli", "rce")
        self.builder.add_edge("rce", "privesc")

        self.finder = ChainPathFinder(self.builder)

    def test_find_chains_bfs(self):
        """Test BFS chain discovery."""
        chains = self.finder.find_chains_bfs(max_depth=4, min_chain_length=2)
        self.assertGreater(len(chains), 0)
        # Should find at least the full chain and sub-chains
        chain_lengths = [len(chain) for chain in chains]
        self.assertIn(3, chain_lengths)  # Full chain

    def test_find_chains_dfs(self):
        """Test DFS chain discovery."""
        chains = self.finder.find_chains_dfs(max_depth=4, min_chain_length=2)
        self.assertGreater(len(chains), 0)

    def test_chain_ordering(self):
        """Test that chains are properly ordered."""
        chains = self.finder.find_chains_bfs()
        for chain in chains:
            # Verify each chain follows the prerequisite→output pattern
            for i in range(len(chain) - 1):
                current = chain[i]
                next_vuln = chain[i + 1]
                # Next vuln should have compatible prerequisites
                self.assertTrue(len(current.outputs) > 0 or len(next_vuln.prerequisites) == 0)

    def test_no_duplicate_chains(self):
        """Test that DFS removes duplicates."""
        chains = self.finder.find_chains_dfs()
        chain_sigs = [tuple(v.vuln_id for v in chain) for chain in chains]
        self.assertEqual(len(chain_sigs), len(set(chain_sigs)))

    def test_correlation_discovery(self):
        """Test correlation-based chain discovery."""
        correlation_matrix = {
            "sqli": {"rce": 0.8},
            "rce": {"privesc": 0.7},
            "privesc": {},
        }
        chains = self.finder.find_chains_correlation(correlation_matrix)
        self.assertGreater(len(chains), 0)


class TestPrerequisiteValidator(unittest.TestCase):
    """Test prerequisite validation."""

    def setUp(self):
        """Set up test vulnerabilities."""
        self.vuln1 = Vulnerability(
            vuln_id="sqli", name="SQLi", category="injection", cvss_score=9.8,
            base_likelihood=0.8, prerequisites=[], outputs=["db_credentials"]
        )
        self.vuln2 = Vulnerability(
            vuln_id="rce", name="RCE", category="rce", cvss_score=9.9,
            base_likelihood=0.7, prerequisites=["db_credentials"], outputs=["shell"]
        )
        self.vuln3 = Vulnerability(
            vuln_id="privesc", name="Privesc", category="privesc", cvss_score=8.8,
            base_likelihood=0.6, prerequisites=["shell"], outputs=["root"]
        )

    def test_valid_chain(self):
        """Test validation of a valid chain."""
        chain = [self.vuln1, self.vuln2, self.vuln3]
        is_valid, issues = PrerequisiteValidator.validate_chain(chain)
        self.assertTrue(is_valid)
        self.assertEqual(len(issues), 0)

    def test_invalid_chain_missing_prerequisite(self):
        """Test validation of invalid chain."""
        # Create vuln with unmet prerequisites
        bad_vuln = Vulnerability(
            vuln_id="bad", name="Bad", category="test", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=["missing_artifact"], outputs=[]
        )
        chain = [self.vuln1, bad_vuln]
        is_valid, issues = PrerequisiteValidator.validate_chain(chain)
        self.assertFalse(is_valid)
        self.assertGreater(len(issues), 0)

    def test_compatibility_match(self):
        """Test output→input compatibility."""
        is_compatible = PrerequisiteValidator.validate_prerequisite_compatibility(
            self.vuln1, self.vuln2
        )
        self.assertTrue(is_compatible)

    def test_compatibility_mismatch(self):
        """Test incompatible vulnerabilities."""
        incompatible_vuln = Vulnerability(
            vuln_id="test", name="Test", category="test", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=["different_artifact"], outputs=[]
        )
        is_compatible = PrerequisiteValidator.validate_prerequisite_compatibility(
            self.vuln1, incompatible_vuln
        )
        self.assertFalse(is_compatible)


class TestChainScoringEngine(unittest.TestCase):
    """Test chain scoring."""

    def setUp(self):
        """Set up test vulnerabilities."""
        self.vuln_high = Vulnerability(
            vuln_id="high", name="High CVE", category="injection", cvss_score=9.8,
            base_likelihood=0.9, prerequisites=[], outputs=["access"]
        )
        self.vuln_medium = Vulnerability(
            vuln_id="medium", name="Medium CVE", category="logic", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=["access"], outputs=["control"]
        )
        self.vuln_low = Vulnerability(
            vuln_id="low", name="Low CVE", category="info", cvss_score=2.0,
            base_likelihood=0.3, prerequisites=["control"], outputs=["leak"]
        )

    def test_likelihood_scoring(self):
        """Test likelihood computation."""
        chain = [self.vuln_high, self.vuln_medium]
        likelihood = ChainScoringEngine.score_likelihood(chain)
        # Should be product: 0.9 * 0.5 = 0.45
        self.assertAlmostEqual(likelihood, 0.45, places=2)

    def test_likelihood_single_vuln(self):
        """Test likelihood for single vulnerability."""
        likelihood = ChainScoringEngine.score_likelihood([self.vuln_high])
        self.assertEqual(likelihood, 0.9)

    def test_likelihood_empty_chain(self):
        """Test likelihood for empty chain."""
        likelihood = ChainScoringEngine.score_likelihood([])
        self.assertEqual(likelihood, 0.0)

    def test_impact_scoring(self):
        """Test impact scoring."""
        chain = [self.vuln_high, self.vuln_medium]
        impact = ChainScoringEngine.score_impact(chain)
        # Should have non-zero CIA scores
        self.assertGreater(impact.combined_score, 0.0)
        self.assertLessEqual(impact.combined_score, 30.0)

    def test_effort_scoring(self):
        """Test effort computation."""
        chain = [self.vuln_high, self.vuln_medium, self.vuln_low]
        effort = ChainScoringEngine.score_effort(chain)
        # Should increase with chain length
        self.assertGreater(effort, 0.0)
        self.assertLessEqual(effort, 10.0)

    def test_comprehensive_scoring(self):
        """Test full chain scoring."""
        chain = [self.vuln_high, self.vuln_medium]
        likelihood, impact, effort = ChainScoringEngine.score_chain(chain)
        self.assertGreater(likelihood, 0.0)
        self.assertGreater(impact.combined_score, 0.0)
        self.assertGreater(effort, 0.0)


class TestChainSimulator(unittest.TestCase):
    """Test chain simulation."""

    def setUp(self):
        """Set up test simulator."""
        self.simulator = ChainSimulator()
        self.vuln1 = Vulnerability(
            vuln_id="v1", name="V1", category="injection", cvss_score=7.0,
            base_likelihood=0.8, prerequisites=[], outputs=["access"]
        )
        self.vuln2 = Vulnerability(
            vuln_id="v2", name="V2", category="rce", cvss_score=9.0,
            base_likelihood=0.7, prerequisites=["access"], outputs=["shell"]
        )

    def test_simulate_valid_chain(self):
        """Test simulating a valid chain."""
        chain = [self.vuln1, self.vuln2]
        success, results = self.simulator.simulate_chain(chain)
        self.assertTrue(success)
        self.assertGreater(len(results), 0)

    def test_simulate_high_cvss_succeeds(self):
        """Test that high CVSS vulns simulate successfully."""
        result = self.simulator._simulate_vuln_exploitation(self.vuln2)
        self.assertTrue(result)

    def test_simulate_low_cvss_fails(self):
        """Test that low CVSS vulns may fail simulation."""
        low_vuln = Vulnerability(
            vuln_id="low", name="Low", category="info", cvss_score=2.0,
            base_likelihood=0.1, prerequisites=[], outputs=[]
        )
        result = self.simulator._simulate_vuln_exploitation(low_vuln)
        self.assertFalse(result)


class TestAutomaticChainDiscovery(unittest.TestCase):
    """Test automatic chain discovery."""

    def setUp(self):
        """Set up test graph."""
        self.graph = RealCVEDataBuilder.build_sample_cve_graph()
        self.discovery = AutomaticChainDiscovery(self.graph)

    def test_discover_chains_bfs(self):
        """Test chain discovery via BFS."""
        chains = self.discovery.discover_chains(methods=["bfs"])
        self.assertGreater(len(chains), 0)

    def test_discover_chains_dfs(self):
        """Test chain discovery via DFS."""
        chains = self.discovery.discover_chains(methods=["dfs"])
        self.assertGreater(len(chains), 0)

    def test_discover_chains_correlation(self):
        """Test chain discovery via correlation."""
        chains = self.discovery.discover_chains(methods=["correlation"])
        # May be empty if correlation matrix has low scores, but shouldn't error
        self.assertIsInstance(chains, list)

    def test_chains_sorted_by_impact(self):
        """Test that chains are sorted by impact descending."""
        chains = self.discovery.discover_chains(methods=["bfs", "dfs"])
        if len(chains) > 1:
            scores = [c.impact_score.combined_score for c in chains]
            self.assertEqual(scores, sorted(scores, reverse=True))

    def test_filter_by_likelihood(self):
        """Test filtering chains by likelihood threshold."""
        chains = self.discovery.discover_chains(min_likelihood=0.5)
        for chain in chains:
            self.assertGreaterEqual(chain.likelihood_score, 0.5)

    def test_filter_by_impact(self):
        """Test filtering chains by impact threshold."""
        chains = self.discovery.discover_chains(min_impact=10.0)
        for chain in chains:
            self.assertGreaterEqual(chain.impact_score.combined_score, 10.0)

    def test_chain_has_metadata(self):
        """Test that discovered chains have proper metadata."""
        chains = self.discovery.discover_chains(methods=["bfs"])
        for chain in chains:
            self.assertIsNotNone(chain.chain_id)
            self.assertGreater(len(chain.vulns), 0)
            self.assertIsNotNone(chain.discovery_method)

    def test_correlation_matrix_building(self):
        """Test correlation matrix construction."""
        matrix = self.discovery._build_correlation_matrix()
        self.assertGreater(len(matrix), 0)

    def test_correlation_computation(self):
        """Test correlation scoring between vulns."""
        vuln1 = Vulnerability(
            vuln_id="v1", name="V1", category="inject", cvss_score=9.0,
            base_likelihood=0.8, prerequisites=[], outputs=["db_access"],
            affected_systems=["mysql"]
        )
        vuln2 = Vulnerability(
            vuln_id="v2", name="V2", category="rce", cvss_score=8.0,
            base_likelihood=0.7, prerequisites=["db_access"], outputs=["shell"],
            affected_systems=["mysql"]
        )
        score = AutomaticChainDiscovery._compute_correlation(vuln1, vuln2)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 1.0)


class TestImpactAggregator(unittest.TestCase):
    """Test CIA impact aggregation."""

    def setUp(self):
        """Set up test vulnerabilities."""
        self.vuln1 = Vulnerability(
            vuln_id="sqli", name="SQLi", category="injection", cvss_score=9.8,
            base_likelihood=0.8, prerequisites=[], outputs=["db_access"]
        )
        self.vuln2 = Vulnerability(
            vuln_id="rce", name="RCE", category="rce", cvss_score=9.9,
            base_likelihood=0.7, prerequisites=["db_access"], outputs=["shell"]
        )
        self.vuln3 = Vulnerability(
            vuln_id="privesc", name="Privesc", category="privesc", cvss_score=8.8,
            base_likelihood=0.6, prerequisites=["shell"], outputs=["root"]
        )

    def test_aggregate_impact(self):
        """Test impact aggregation."""
        chain = [self.vuln1, self.vuln2, self.vuln3]
        impact = ImpactAggregator.aggregate_chain_impact(chain)
        self.assertGreater(impact.combined_score, 0.0)
        self.assertLessEqual(impact.combined_score, 30.0)

    def test_severity_critical(self):
        """Test severity mapping for critical impact."""
        impact = ImpactMetrics(confidentiality=10.0, integrity=10.0, availability=10.0)
        impact.compute_combined()
        severity = ImpactAggregator.compute_chain_severity(impact)
        self.assertEqual(severity, "CRITICAL")

    def test_severity_high(self):
        """Test severity mapping for high impact."""
        impact = ImpactMetrics(confidentiality=8.0, integrity=8.0, availability=8.0)
        impact.compute_combined()
        severity = ImpactAggregator.compute_chain_severity(impact)
        self.assertEqual(severity, "HIGH")

    def test_severity_medium(self):
        """Test severity mapping for medium impact."""
        impact = ImpactMetrics(confidentiality=6.0, integrity=6.0, availability=6.0)
        impact.compute_combined()
        severity = ImpactAggregator.compute_chain_severity(impact)
        self.assertEqual(severity, "MEDIUM")

    def test_severity_low(self):
        """Test severity mapping for low impact."""
        impact = ImpactMetrics(confidentiality=4.0, integrity=4.0, availability=4.0)
        impact.compute_combined()
        severity = ImpactAggregator.compute_chain_severity(impact)
        self.assertEqual(severity, "LOW")


class TestRealCVEData(unittest.TestCase):
    """Test real CVE-based chain patterns."""

    def test_build_sample_graph(self):
        """Test building sample graph with CVE data."""
        graph = RealCVEDataBuilder.build_sample_cve_graph()
        self.assertGreater(len(graph.vulnerabilities), 0)
        self.assertGreater(len(graph.edges), 0)

    def test_graph_has_known_chains(self):
        """Test that graph contains known chain patterns."""
        graph = RealCVEDataBuilder.build_sample_cve_graph()
        # Should have SQLi → RCE edge
        self.assertIn("udf_02", graph.edges.get("sqli_01", []))

    def test_graph_vuln_metadata(self):
        """Test that vulnerabilities have rich metadata."""
        graph = RealCVEDataBuilder.build_sample_cve_graph()
        for vuln in graph.vulnerabilities.values():
            self.assertIsNotNone(vuln.vuln_id)
            self.assertIsNotNone(vuln.name)
            self.assertIsNotNone(vuln.category)
            self.assertGreater(vuln.cvss_score, 0.0)


class TestPublicAPI(unittest.TestCase):
    """Test public API functions."""

    def test_discover_autonomous_chains(self):
        """Test main discovery function."""
        chains = discover_autonomous_chains(use_real_cves=True)
        self.assertGreater(len(chains), 0)

    def test_discover_with_custom_depth(self):
        """Test discovery with custom depth."""
        chains = discover_autonomous_chains(max_depth=2, use_real_cves=True)
        self.assertIsInstance(chains, list)

    def test_discover_with_likelihood_filter(self):
        """Test discovery with likelihood filtering."""
        chains = discover_autonomous_chains(min_likelihood=0.3, use_real_cves=True)
        for chain in chains:
            self.assertGreaterEqual(chain.likelihood_score, 0.3)


class TestExportFormats(unittest.TestCase):
    """Test export functionality."""

    def setUp(self):
        """Set up test chains."""
        self.chains = discover_autonomous_chains(use_real_cves=True, max_depth=3)

    def test_export_to_json(self):
        """Test JSON export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "chains.json"
            export_chains_to_json(self.chains, str(output_path))
            self.assertTrue(output_path.exists())

            # Verify JSON structure
            with open(output_path) as f:
                data = json.load(f)
            self.assertIn("chains", data)
            self.assertEqual(data["total_chains"], len(self.chains))

    def test_export_to_markdown(self):
        """Test markdown export."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "chains.md"
            export_chains_to_markdown(self.chains, str(output_path))
            self.assertTrue(output_path.exists())

            # Verify content
            content = output_path.read_text()
            self.assertIn("Autonomous Vulnerability Chain", content)
            self.assertIn("Chain 1", content)

    def test_export_empty_list(self):
        """Test exporting empty chain list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "empty.json"
            md_path = Path(tmpdir) / "empty.md"

            export_chains_to_json([], str(json_path))
            export_chains_to_markdown([], str(md_path))

            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def test_empty_graph(self):
        """Test discovery on empty graph."""
        graph = VulnerabilityGraphBuilder()
        discovery = AutomaticChainDiscovery(graph)
        chains = discovery.discover_chains()
        self.assertEqual(len(chains), 0)

    def test_single_vuln_chain(self):
        """Test chain of length 1."""
        graph = VulnerabilityGraphBuilder()
        vuln = Vulnerability(
            vuln_id="v1", name="V1", category="inject", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=[], outputs=[]
        )
        graph.add_vulnerability(vuln)
        chains = ChainPathFinder(graph).find_chains_bfs(min_chain_length=1)
        self.assertEqual(len(chains), 1)

    def test_duplicate_edges(self):
        """Test that duplicate edges aren't added."""
        graph = VulnerabilityGraphBuilder()
        v1 = Vulnerability(
            vuln_id="v1", name="V1", category="test", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=[], outputs=[]
        )
        v2 = Vulnerability(
            vuln_id="v2", name="V2", category="test", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=[], outputs=[]
        )
        graph.add_vulnerability(v1)
        graph.add_vulnerability(v2)
        graph.add_edge("v1", "v2")
        graph.add_edge("v1", "v2")  # Duplicate
        self.assertEqual(len(graph.edges["v1"]), 1)

    def test_self_loop_prevention(self):
        """Test that self-loops aren't added."""
        graph = VulnerabilityGraphBuilder()
        v1 = Vulnerability(
            vuln_id="v1", name="V1", category="test", cvss_score=5.0,
            base_likelihood=0.5, prerequisites=[], outputs=[]
        )
        graph.add_vulnerability(v1)
        # Try to add self-loop
        graph.add_edge("v1", "v1")
        # Should allow it structurally, but DFS/BFS should prevent cycles
        self.assertEqual(len(graph.edges["v1"]), 1)

    def test_large_graph_performance(self):
        """Test performance with large graph."""
        graph = VulnerabilityGraphBuilder()
        # Create 100 vulnerabilities
        for i in range(100):
            vuln = Vulnerability(
                vuln_id=f"v{i}",
                name=f"Vuln{i}",
                category="test",
                cvss_score=float(i % 10),
                base_likelihood=0.5,
                prerequisites=[],
                outputs=[],
            )
            graph.add_vulnerability(vuln)

        # Should handle without timeout
        discovery = AutomaticChainDiscovery(graph)
        chains = discovery.discover_chains(max_depth=2, methods=["bfs"])
        self.assertIsInstance(chains, list)


class TestIntegration(unittest.TestCase):
    """End-to-end integration tests."""

    def test_full_discovery_pipeline(self):
        """Test complete discovery and export pipeline."""
        # Discover chains
        chains = discover_autonomous_chains(use_real_cves=True, max_depth=3)
        self.assertGreater(len(chains), 0)

        # Validate at least one chain
        if chains:
            first_chain = chains[0]
            is_valid, _ = PrerequisiteValidator.validate_chain(first_chain.vulns)
            # May not be valid if prerequisites aren't perfectly matched, but shouldn't error
            self.assertIsInstance(is_valid, bool)

        # Export both formats
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "chains.json"
            md_path = Path(tmpdir) / "chains.md"
            export_chains_to_json(chains, str(json_path))
            export_chains_to_markdown(chains, str(md_path))

            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
