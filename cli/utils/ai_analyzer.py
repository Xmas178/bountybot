"""
AI-powered analysis using Claude API for intelligent finding prioritization.

Uses Claude Sonnet 4.5 to analyze security findings and suggest the most
promising targets for manual testing.
"""

import os
import json
from typing import List, Dict, Optional
from anthropic import Anthropic


class AIAnalyzer:
    """AI analyzer for security findings using Claude Sonnet 4.5."""

    def __init__(self):
        """Initialize Claude API client."""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set in .env file. "
                "Get your API key from https://console.anthropic.com/"
            )

        self.client = Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"

    def prioritize_findings(
        self, scan, top_n: int = 10, min_severity: Optional[str] = None
    ) -> List[Dict]:
        """
        Prioritize findings using AI analysis.

        Args:
            scan: Scan model instance
            top_n: Number of top findings to return (1-20)
            min_severity: Minimum severity filter

        Returns:
            List of prioritized findings with:
            - rank: 1-10
            - finding: Finding object
            - reasoning: Why this is important (1-2 sentences)
            - action: What to do (specific steps)
            - time_estimate: How long to test
            - bounty_range: Estimated payout
        """
        from findings.models import Finding

        # Get findings
        findings = Finding.objects.filter(scan=scan).order_by("-severity", "id")

        if min_severity:
            severity_order = ["info", "low", "medium", "high", "critical"]
            min_index = severity_order.index(min_severity.lower())
            allowed_severities = severity_order[min_index:]
            findings = findings.filter(severity__in=allowed_severities)

        if findings.count() == 0:
            return []

        # Prepare findings data for AI (limit to avoid token limits)
        findings_data = []
        for f in findings[:200]:  # Max 200 findings
            findings_data.append(
                {
                    "id": f.id,
                    "severity": f.severity,
                    "title": f.title,
                    "description": (
                        f.description[:300] if f.description else ""
                    ),  # Truncate
                    "tool": f.discovered_by,
                    "affected_url": f.affected_url or "",
                    "cvss_score": f.cvss_score,
                }
            )

        # Get technologies from scan
        technologies = self._extract_technologies(scan)

        # Build AI prompt
        prompt = self._build_prioritization_prompt(
            findings_data=findings_data,
            technologies=technologies,
            target_name=scan.target.name,
            target_type=scan.target.target_type,
            top_n=top_n,
        )

        # Call Claude API
        response = self._call_claude(prompt)

        # Parse AI response
        prioritized = self._parse_prioritization_response(response, findings)

        return prioritized[:top_n]

    def _extract_technologies(self, scan) -> List[str]:
        """Extract detected technologies from scan findings."""
        from findings.models import Finding

        # Get WhatWeb findings
        whatweb_findings = Finding.objects.filter(scan=scan, discovered_by="whatweb")

        technologies = set()
        for f in whatweb_findings:
            desc = f.description or ""

            # Extract from description
            if "WordPress" in desc:
                technologies.add("WordPress")
            if "React" in desc:
                technologies.add("React")
            if "PostgreSQL" in desc or "Postgres" in desc:
                technologies.add("PostgreSQL")
            if "MySQL" in desc:
                technologies.add("MySQL")
            if "nginx" in desc:
                technologies.add("nginx")
            if "Apache" in desc:
                technologies.add("Apache")
            if "PHP" in desc:
                technologies.add("PHP")
            if "Node.js" in desc or "Express" in desc:
                technologies.add("Node.js")

        return list(technologies)

    def _build_prioritization_prompt(
        self,
        findings_data: List[Dict],
        technologies: List[str],
        target_name: str,
        target_type: str,
        top_n: int,
    ) -> str:
        """Build AI prompt for finding prioritization."""

        findings_json = json.dumps(findings_data, indent=2)
        tech_list = ", ".join(technologies) if technologies else "Unknown"

        prompt = f"""You are an expert bug bounty hunter analyzing security scan results.

TARGET INFORMATION:
- Name: {target_name}
- Type: {target_type}
- Technologies: {tech_list}

FINDINGS ({len(findings_data)} total):
{findings_json}

TASK:
Prioritize the TOP {top_n} findings for manual testing based on:
1. Severity (critical > high > medium > low > info)
2. Exploitability (easy to test and verify)
3. Business impact (payment systems > admin panels > info disclosure)
4. Bounty potential (typical bug bounty payouts)
5. Time efficiency (quick wins vs deep dives)

For each of the TOP {top_n} findings, provide:
1. finding_id: The ID from the findings list
2. reasoning: Why this is important (max 150 chars, concise)
3. action: Specific manual testing steps (max 200 chars, actionable)
4. time_estimate: How long to test (e.g., "15-30 min")
5. bounty_range: Estimated payout (e.g., "$500-5k")

RESPONSE FORMAT (JSON only, no markdown):
{{
  "prioritized": [
    {{
      "finding_id": 123,
      "reasoning": "Payment endpoint with SQLi, PostgreSQL backend allows data extraction",
      "action": "Burp Suite: test order_id param with UNION SELECT for user data",
      "time_estimate": "30-45 min",
      "bounty_range": "$5k-25k"
    }}
  ]
}}

Be specific and actionable. Focus on manual testing steps a bug bounty hunter would do.
Keep reasoning and action fields CONCISE.
"""

        return prompt

    def _call_claude(self, prompt: str) -> str:
        """Call Claude API and return response."""

        message = self.client.messages.create(
            model=self.model,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )

        return message.content[0].text

    def _parse_prioritization_response(self, ai_response: str, findings) -> List[Dict]:
        """Parse AI response and build prioritized list."""

        # Parse JSON response
        try:
            # Try direct JSON parse
            data = json.loads(ai_response)
            prioritized_data = data.get("prioritized", [])
        except json.JSONDecodeError:
            # Fallback: try to extract JSON from markdown code blocks
            import re

            json_match = re.search(r"```json\s*(\{.*?\})\s*```", ai_response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(1))
                prioritized_data = data.get("prioritized", [])
            else:
                # Try to find any JSON object
                json_match = re.search(r"\{.*\}", ai_response, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group(0))
                    prioritized_data = data.get("prioritized", [])
                else:
                    raise ValueError("Could not parse AI response as JSON")

        # Build result list
        results = []
        for rank, item in enumerate(prioritized_data, 1):
            finding_id = item.get("finding_id")
            if not finding_id:
                continue

            # Get finding object
            try:
                finding = findings.get(id=finding_id)
            except:
                continue

            results.append(
                {
                    "rank": rank,
                    "finding": finding,
                    "reasoning": item.get("reasoning", "No reasoning provided"),
                    "action": item.get("action", "Manual testing required"),
                    "time_estimate": item.get("time_estimate", "Unknown"),
                    "bounty_range": item.get("bounty_range", "Unknown"),
                }
            )

        return results
