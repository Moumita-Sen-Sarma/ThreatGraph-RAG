from __future__ import annotations

from threatgraph.llm.client import LLMClient
from threatgraph.retrieval.graph import GraphRetriever


class GraphRAG:
    """
    Graph-based Retrieval-Augmented Generation.

    Pipeline:
        question
        -> graph retrieval
        -> graph evidence
        -> LLM answer
    """

    def __init__(
        self,
        retriever: GraphRetriever,
        llm: LLMClient,
    ) -> None:
        self.retriever = retriever
        self.llm = llm
    
    def retrieve_group_techniques(
        self,
        group_name: str,
    ) -> list[dict]:
        return self.retriever.get_group_techniques(group_name)

    def retrieve_group_software(
        self,
        group_name: str,
    ) -> list[dict]:
        return self.retriever.get_group_software(
            group_name
        )

    def retrieve_technique_mitigations(
        self,
        technique_id: str,
    ) -> list[dict]:
        return (
            self.retriever
            .get_technique_mitigations(
                technique_id
            )
        )
    
    def _format_group_techniques(
        self,
        group_name: str,
        rows: list[dict],
    ) -> str:

        if not rows:
            return (
                f"No attack techniques were found "
                f"for threat group {group_name}."
            )

        lines = [
            f"Threat group: {group_name}",
            "Associated techniques:",
        ]

        for row in rows:
            lines.append(
                f"- {row['technique_id']}: "
                f"{row['technique_name']}"
            )

        return "\n".join(lines)

    

    def answer_group_techniques(
        self,
        group_name: str,
    ) -> dict:

        rows = self.retrieve_group_techniques(
            group_name
        )

        context = self._format_group_techniques(
            group_name,
            rows,
        )

        instructions = """
            You are ThreatGraph, a defensive cyber threat
            intelligence assistant.

            Answer using ONLY the graph evidence provided.

            Rules:
            1. Do not add facts not present in the graph evidence.
            2. If evidence is missing, say so.
            3. Keep ATT&CK IDs when available.
            4. Be concise and factual.
            """

        prompt = f"""
            QUESTION:

            What attack techniques are associated with
            {group_name}?


            GRAPH EVIDENCE:

            {context}


            Answer using only the graph evidence.
            """

        answer = self.llm.generate(
            instructions=instructions,
            prompt=prompt,
        )

        return {
            "answer": answer,
            "graph_evidence": rows,
        }

    def answer_group_software(
    self,
    group_name: str,
) -> dict:
        rows = self.retriever.get_group_software(
            group_name
        )

        if rows:
            evidence_lines = [
                f"- {row['software_name']}"
                for row in rows
            ]
            context = (
                f"Threat group: {group_name}\n"
                "Associated software:\n"
                + "\n".join(evidence_lines)
            )
        else:
            context = (
                f"No software was found for "
                f"{group_name}."
            )

        instructions = """
            You are ThreatGraph, a defensive cyber threat
            intelligence assistant.

            Answer using ONLY the graph evidence provided.

            Rules:
            1. Do not add unsupported facts.
            2. If evidence is missing, say so.
            3. Be concise and factual.
            """

        prompt = f"""
            QUESTION:

            What software is associated with {group_name}?


            GRAPH EVIDENCE:

            {context}


            Answer using only the graph evidence.
            """

        answer = self.llm.generate(
            instructions=instructions,
            prompt=prompt,
        )

        return {
            "answer": answer,
            "graph_evidence": rows,
        }

    def answer_technique_mitigations(
    self,
    technique_id: str,
) -> dict:
        rows = (
            self.retriever
            .get_technique_mitigations(
                technique_id
            )
        )

        if rows:
            evidence_lines = [
                (
                    f"- {row['mitigation_id']}: "
                    f"{row['mitigation_name']}"
                )
                for row in rows
            ]

            context = (
                f"Technique: {technique_id}\n"
                "Associated mitigations:\n"
                + "\n".join(evidence_lines)
            )
        else:
            context = (
                f"No mitigations were found for "
                f"{technique_id}."
            )

        instructions = """
            You are ThreatGraph, a defensive cyber threat
            intelligence assistant.

            Answer using ONLY the graph evidence provided.

            Rules:
            1. Do not add unsupported facts.
            2. If evidence is missing, say so.
            3. Keep mitigation IDs when available.
            4. Be concise and factual.
            """

        prompt = f"""
            QUESTION:

            What mitigations are associated with
            {technique_id}?


            GRAPH EVIDENCE:

            {context}


            Answer using only the graph evidence.
            """

        answer = self.llm.generate(
            instructions=instructions,
            prompt=prompt,
        )

        return {
            "answer": answer,
            "graph_evidence": rows,
        }