from __future__ import annotations

import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()


class LLMClient:
    """
    Small wrapper around the LLM provider.

    Keeping LLM-specific code here means the rest of
    ThreatGraph does not depend directly on OpenAI.
    """

    def __init__(self) -> None:
        self.client = OpenAI(
            api_key=os.environ["OPENAI_API_KEY"]
        )

        self.model = "gpt-5.6-luna"

    def generate(
        self,
        instructions: str,
        prompt: str,
    ) -> str:
        response = self.client.responses.create(
            model=self.model,
            instructions=instructions,
            input=prompt,
        )

        return response.output_text