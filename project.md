# ThreatGraph-RAG

## Objective

Build an evidence-grounded cyber threat intelligence system combining:

- Knowledge Graphs
- Vector RAG
- Hybrid Graph-RAG
- LLM-based knowledge extraction
- MCP tools
- Security guardrails
- Quantitative evaluation

## Initial Data Sources

- MITRE ATT&CK
- CISA Known Exploited Vulnerabilities

## Research Question

Does hybrid graph + vector retrieval improve cyber threat intelligence question answering compared with vector-only RAG?

## MVP

1. Parse MITRE ATT&CK STIX data
2. Normalize CTI entities and relationships
3. Build a Neo4j knowledge graph
4. Ingest CISA KEV
5. Build Qdrant vector retrieval
6. Implement Vector RAG baseline
7. Implement graph retrieval
8. Implement Hybrid Graph-RAG
9. Add LLM-based entity/relation extraction
10. Add security guardrails
11. Expose CTI capabilities through MCP
12. Evaluate retrieval and answer quality

## Day 1 Scope

- Repository setup
- CTI schema
- MITRE ATT&CK download
- MITRE ATT&CK parsing
- Basic unit tests

## Constraints

- Defensive cybersecurity use only
- Preserve source provenance
- No unsupported graph edges
- Keep ingestion separate from storage
- Add tests for major components
