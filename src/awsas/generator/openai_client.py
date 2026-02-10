from typing import Any, Dict, List
import os
from openai import OpenAI

DEFAULT_MODEL = "gpt-5.1"  # jak u Ciebie

class OpenAIPayloadGenerator:
    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise RuntimeError(
                "Brak API key: ustaw zmienną środowiskową OPENAI_API_KEY lub przekaż api_key."
            )
        self.client = OpenAI(api_key=self.api_key)
        self.model = model

    def generate(self, input_blocks: List[Dict[str, Any]]) -> str:
        resp = self.client.responses.create(
            model=self.model,
            input=input_blocks,
        )

        try:
            return resp.output_text
        except AttributeError:
            texts: List[str] = []
            for out in getattr(resp, "output", []) or []:
                content = getattr(out, "content", None)
                if not content:
                    continue
                for part in content:
                    if getattr(part, "type", None) == "output_text":
                        texts.append(part.text)
            return "\n".join(texts)