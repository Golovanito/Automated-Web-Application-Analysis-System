import os
from typing import List, Dict, Any

from anthropic import Anthropic


class ClaudeClient:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise RuntimeError("Brak ANTHROPIC_API_KEY w środowisku ani w parametrze.")

        self.model = model or os.getenv("CLAUDE_MODEL") or "claude-sonnet-4-5-20250929"

        if not isinstance(self.model, str):
            raise TypeError(
                f"Parametr model musi być str, a jest {type(self.model)}: {self.model!r}"
            )

        self.client = Anthropic(api_key=self.api_key)

    def _blocks_to_messages(self, input_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        system_texts: List[str] = []
        user_texts: List[str] = []

        for b in input_blocks:
            role = b.get("role", "user")
            content = b.get("content", "")

            if isinstance(content, list):
                texts = []
                for c in content:
                    if isinstance(c, dict) and "text" in c:
                        texts.append(str(c["text"]))
                    else:
                        texts.append(str(c))
                content_str = "\n".join(texts)
            elif isinstance(content, str):
                content_str = content
            else:
                content_str = str(content)

            if role == "system":
                system_texts.append(content_str)
            elif role == "assistant":
                user_texts.append(f"[assistant context]\n{content_str}")
            else:
                user_texts.append(content_str)

        system_prompt = "\n".join(system_texts) if system_texts else \
            "You are a security test generator. Respond ONLY with valid JSON."
        user_prompt = "\n\n".join(user_texts)

        return {
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": user_prompt}
                    ],
                }
            ],
        }

    def generate(self, input_blocks: List[Dict[str, Any]]) -> str:
        payload = self._blocks_to_messages(input_blocks)

        # print("DEBUG model:", repr(self.model), type(self.model))

        resp = self.client.messages.create(
            model=self.model,
            max_tokens=4048,
            temperature=0.2,
            system=payload["system"],
            messages=payload["messages"],
        )

        texts: List[str] = []
        for block in resp.content:
            if block.type == "text":
                texts.append(block.text)

        return "\n".join(texts)