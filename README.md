# ThreatGraph-RAG

ThreatGraph-RAG is an evidence-grounded cyber threat intelligence system that combines **Knowledge Graphs, Retrieval-Augmented Generation (RAG), LLMs, MCP, and security guardrails**.

The project uses public threat intelligence sources such as **MITRE ATT&CK** and **CISA Known Exploited Vulnerabilities (KEV)** to support structured threat analysis and evidence-backed question answering.

## Goals

- Build a cyber threat intelligence knowledge graph
- Implement vector-based RAG for semantic retrieval
- Combine graph and vector retrieval using hybrid Graph-RAG
- Generate source-grounded LLM responses
- Extract entities and relationships from unstructured threat reports
- Expose threat-intelligence capabilities through MCP tools
- Add guardrails for prompt injection, unsupported claims, and unsafe requests
- Compare Vector RAG, Graph Retrieval, and Hybrid Graph-RAG quantitatively

## Planned Architecture

```text
MITRE ATT&CK ──┐
               ├── Knowledge Graph (Neo4j)
CISA KEV ──────┘

Threat Intelligence Text
        │
        └── Embeddings → Qdrant

Neo4j + Qdrant
      │
      ↓
Hybrid Graph-RAG
      │
      ↓
     LLM
      │
      ↓
Guardrails
      │
      ↓
Evidence-grounded response

        +
    MCP Server
```
Tech Stack:

Python

Neo4j

Qdrant

Sentence Transformers

LLM APIs / local LLMs

Model Context Protocol (MCP)

FastAPI

Pydantic

Pytest

Data Sources

MITRE ATT&CK

CISA Known Exploited Vulnerabilities (KEV)

Additional public threat intelligence reports

Evaluation

The project will compare:


Vector RAG

Knowledge Graph retrieval

Hybrid Graph-RAG

using metrics such as:

Recall@K

MRR

Hit@K

Answer correctness

Faithfulness

Citation accuracy