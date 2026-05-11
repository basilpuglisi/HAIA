"""
HAIA Agent Framework - Navigator Router
=========================================
Operation 3 (Route): Delivers all platform responses to the
designated Navigator for synthesis.

The router does NOT choose which responses to forward. It forwards ALL.
The Navigator does NOT resolve disagreements. It presents them.
Resolution is a human governance decision.

The structured synthesis prompt enforces the governance output format:
convergence, divergence, dissent, sources, conflicts, confidence,
recommendation, and expiry.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

from typing import Optional

from .adapters import PlatformAdapter, AdapterResponse


# The synthesis prompt is deterministic infrastructure, not cognitive work.
# It instructs the Navigator platform on output structure.
# The router sends this prompt. It does not evaluate the response.

NAVIGATOR_SYNTHESIS_PROMPT = """You are operating as the Navigator in a HAIA-RECCLIN multi-AI governance workflow. Your role is to synthesize responses from multiple independent AI platforms into a structured governance output.

You have received responses from {platform_count} platforms for the following task:

RECCLIN ROLE: {recclin_role}
ORIGINAL PROMPT: {original_prompt}

PLATFORM RESPONSES:
{platform_responses}

Produce a structured synthesis with the following sections. Do not resolve disagreements. Present them for human arbitration.

CONVERGENCE: Where do the platforms agree? What findings, claims, or recommendations appear across multiple responses?

DIVERGENCE: Where do the platforms disagree? What claims appear in one response but are contradicted or absent in others? Identify the specific platforms on each side.

DISSENT: Document any minority position in full. Do not suppress or summarize away dissenting views. If one platform disagrees with the others, preserve that disagreement with the platform's reasoning.

SOURCES: What sources, references, or evidence do the platforms cite? Flag any unverified claims as [PROVISIONAL].

CONFLICTS: Are there direct contradictions between platform responses? List each conflict with the platforms involved.

CONFIDENCE: On a scale of 0 to 100, how confident should the human decision-maker be in the convergent findings? Justify the score based on: agreement level across platforms, quality of evidence cited, and presence or absence of contradictions.

RECOMMENDATION: Present the platform recommendations. Suggest one with rationale. Clearly label this as AI-generated and subject to human arbitration. The human is not bound by this recommendation.

EXPIRY: Is this information time-sensitive? Note any expiration conditions."""


class NavigatorRouter:
    """
    Routes all platform responses to the Navigator for synthesis.

    Operation 3 (Route): The router delivers responses. It does not
    choose which responses to forward. It forwards all of them.

    The Navigator is a designated AI platform (configurable, currently
    defaulting to Claude based on demonstrated synthesis capability).
    Navigator assignment is a Checkpoint-Based Governance decision
    subject to reevaluation.
    """

    def __init__(self, navigator_adapter: PlatformAdapter):
        """
        Args:
            navigator_adapter: The platform adapter for the Navigator.
                               Must be a registered, functional adapter.
        """
        self.navigator_adapter = navigator_adapter

    def route_for_synthesis(
        self,
        original_prompt: str,
        recclin_role: str,
        platform_responses: list[AdapterResponse],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> AdapterResponse:
        """
        Route all platform responses to the Navigator for synthesis.

        Constructs the synthesis prompt from the template, inserts all
        platform responses verbatim, and sends to the Navigator.

        Args:
            original_prompt: The exact prompt that was dispatched to platforms
            recclin_role: The RECCLIN role for this task
            platform_responses: All responses collected from platforms (unfiltered)
            system_prompt: Optional additional system context for Navigator
            max_tokens: Maximum tokens for the synthesis response

        Returns:
            AdapterResponse from the Navigator containing the structured synthesis
        """
        # Format platform responses for insertion into the synthesis prompt
        formatted_responses = self._format_responses(platform_responses)

        # Build the synthesis prompt
        synthesis_prompt = NAVIGATOR_SYNTHESIS_PROMPT.format(
            platform_count=len(platform_responses),
            recclin_role=recclin_role,
            original_prompt=original_prompt,
            platform_responses=formatted_responses,
        )

        # Route to Navigator (Operation 3)
        # The router sends the prompt. It does not evaluate the response.
        nav_system = (
            "You are the Navigator in a HAIA-RECCLIN governance workflow. "
            "Your synthesis will be reviewed by a human at a governance checkpoint. "
            "Do not resolve disagreements. Present them for human arbitration."
        )
        if system_prompt:
            nav_system = f"{nav_system}\n\n{system_prompt}"

        return self.navigator_adapter.send_prompt(
            prompt=synthesis_prompt,
            system_prompt=nav_system,
            max_tokens=max_tokens,
        )

    def _format_responses(self, responses: list[AdapterResponse]) -> str:
        """
        Format all platform responses for insertion into the synthesis prompt.
        Every response is included verbatim. None are filtered or omitted.
        """
        sections = []
        for i, resp in enumerate(responses, 1):
            status = "SUCCESS" if resp.success else f"ERROR: {resp.error_detail}"
            section = (
                f"--- PLATFORM {i}: {resp.platform_id} ({resp.platform_model}) ---\n"
                f"STATUS: {status}\n"
                f"RESPONSE HASH: {resp.response_hash}\n"
            )
            if resp.success:
                section += f"RESPONSE:\n{resp.response_text}\n"
            else:
                section += f"ERROR DETAIL: {resp.error_detail}\n"
            sections.append(section)

        return "\n".join(sections)
