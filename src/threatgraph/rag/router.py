from __future__ import annotations

import json

from threatgraph.llm.client import LLMClient
from threatgraph.rag.query_models import GraphQuery


class QueryRouter:
    """
    Convert a natural-language CTI question
    into a structured GraphQuery.
    """

    def __init__(
        self,
        llm: LLMClient,
    ) -> None:
        self.llm = llm

    def route(
        self,
        question: str,
    ) -> GraphQuery:
        """
        Determine the graph intent and extract
        relevant entities from the question.
        """

        instructions = """
You are a routing component for a cyber threat
intelligence system.

Your ONLY task is to convert the user's question
into structured JSON.

Do not answer the cybersecurity question.

Supported intents:

1. group_techniques
   The user asks which attack techniques are
   associated with a threat group.

2. group_software
   The user asks which software/tools are associated
   with a threat group.

3. technique_mitigations
   The user asks which mitigations apply to a
   particular attack technique.

4. group_technique_mitigations
   The user mentions both a threat group and a
   specific technique and asks about mitigations.

5. unknown
   The question does not match the supported intents.

Return ONLY valid JSON.

Required JSON fields:

{
    "intent": "...",
    "group_name": null or string,
    "technique": null or string
}

Do not include Markdown.
Do not include explanations.
"""

        prompt = f"""
User question:

{question}
"""

        response = self.llm.generate(
            instructions=instructions,
            prompt=prompt,
        )

        # Convert the LLM's JSON string
        # into a Python dictionary.
        parsed = json.loads(
            response
        )

        # Validate that the dictionary follows
        # our GraphQuery schema.
        return GraphQuery.model_validate(
            parsed
        )