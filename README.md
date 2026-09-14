# ThreatGraph-RAG

## Project Overview

**ThreatGraph-RAG** is an evidence-grounded Cyber Threat Intelligence (CTI) system that combines:

- Large Language Models (LLMs)
- Retrieval-Augmented Generation (RAG)
- Knowledge Graphs
- Hybrid Graph + Vector Retrieval
- LLM-based Knowledge Extraction
- Model Context Protocol (MCP)
- Security Guardrails
- Quantitative Evaluation

The system integrates structured and unstructured cybersecurity information to answer threat-intelligence questions with traceable evidence.

The primary goal is not to build a generic cybersecurity chatbot.

The goal is to investigate whether combining **graph-based retrieval with semantic vector retrieval** improves factual accuracy, multi-hop reasoning, and evidence grounding compared with traditional vector-only RAG.

---

# 1. Motivation

Cyber Threat Intelligence is distributed across heterogeneous sources such as:

- MITRE ATT&CK
- CISA Known Exploited Vulnerabilities (KEV)
- CVE/NVD vulnerability descriptions
- Security advisories
- Threat reports

These sources contain both structured relationships and large amounts of descriptive text.

Traditional vector-based RAG is useful for semantic retrieval but may struggle with relationship-heavy questions such as:

> Which ATT&CK techniques are used by APT29, and what mitigations exist for those techniques?

Such a question requires explicit traversal between several entities:

```text
Threat Group
    ↓ USES
Attack Technique
    ↓ MITIGATED_BY
Mitigation