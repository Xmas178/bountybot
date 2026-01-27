"""
PoC (Proof of Concept) Generator using Claude API.

Generates executable exploit scripts and report templates for security findings.
"""

import os
import json
from pathlib import Path
from typing import Dict, Optional
from anthropic import Anthropic
from datetime import datetime


class PoCGenerator:
    """Generate PoC scripts and reports using Claude API."""

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

        # Output directory
        self.output_dir = Path.home() / "Työpöytä" / "projects" / "bountybot" / "pocs"
        self.output_dir.mkdir(exist_ok=True)

    def generate_poc(
        self, finding, output_path: Optional[str] = None, format: str = "python"
    ) -> Dict:
        """
        Generate PoC for a finding.

        Args:
            finding: Finding model instance
            output_path: Custom output file path
            format: PoC format (python, bash, curl, report)

        Returns:
            Dict with success status, file_path, and format
        """
        # Build prompt based on format
        if format == "report":
            prompt = self._build_report_prompt(finding)
            extension = "md"
        elif format == "bash":
            prompt = self._build_bash_prompt(finding)
            extension = "sh"
        elif format == "curl":
            prompt = self._build_curl_prompt(finding)
            extension = "sh"
        else:  # python (default)
            prompt = self._build_python_prompt(finding)
            extension = "py"

        # Call Claude API
        try:
            response = self._call_claude(prompt)
        except Exception as e:
            return {"success": False, "error": f"Claude API error: {str(e)}"}

        # Generate filename
        if output_path:
            file_path = Path(output_path)
        else:
            # Auto-generate filename
            safe_title = self._sanitize_filename(finding.title)
            filename = f"poc_{finding.id}_{safe_title}.{extension}"
            file_path = self.output_dir / filename

        # Extract code from response (remove markdown fences)
        code = self._extract_code(response, extension)

        # Write to file
        try:
            file_path.write_text(code, encoding="utf-8")

            # Make executable if bash/python
            if extension in ["sh", "py"]:
                os.chmod(file_path, 0o755)

            return {"success": True, "file_path": str(file_path), "format": format}
        except Exception as e:
            return {"success": False, "error": f"File write error: {str(e)}"}

    def _build_python_prompt(self, finding) -> str:
        """Build prompt for Python PoC generation."""

        return f"""Generate a Python proof-of-concept script for this security finding:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Category: {finding.category}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}
- Affected Parameter: {finding.affected_parameter or 'N/A'}
- Tool: {finding.discovered_by or 'N/A'}

REQUIREMENTS:
1. Create a working Python script (Python 3.12+)
2. Use requests library for HTTP operations
3. Include clear comments explaining each step
4. Add TODO markers for manual customization
5. Include error handling
6. Print results clearly
7. Add ethical disclaimer at top
8. Make it educational and safe (no destructive actions)

FORMAT:
- Return ONLY the Python code
- No markdown fences
- Start with shebang: #!/usr/bin/env python3
- Include docstring explaining the vulnerability

Focus on demonstrating the vulnerability exists, NOT exploitation.
"""

    def _build_bash_prompt(self, finding) -> str:
        """Build prompt for Bash PoC generation."""

        return f"""Generate a Bash shell script for this security finding:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}

REQUIREMENTS:
1. Create a working Bash script
2. Use curl for HTTP operations
3. Include clear comments
4. Add TODO markers for customization
5. Print results clearly
6. Add ethical disclaimer
7. Make it safe and educational

FORMAT:
- Return ONLY the Bash code
- No markdown fences
- Start with: #!/bin/bash
- Include comments explaining vulnerability
"""

    def _build_curl_prompt(self, finding) -> str:
        """Build prompt for cURL command generation."""

        return f"""Generate cURL commands to demonstrate this vulnerability:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}
- Parameter: {finding.affected_parameter or 'N/A'}

REQUIREMENTS:
1. Provide 3-5 cURL commands showing the vulnerability
2. Include comments explaining each command
3. Show expected responses
4. Make it copy-paste ready
5. Include ethical disclaimer

FORMAT:
- Return as a shell script with cURL commands
- No markdown fences
- Start with #!/bin/bash
"""

    def _build_report_prompt(self, finding) -> str:
        """Build prompt for HackerOne report generation."""

        return f"""Generate a professional bug bounty report for this finding:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Category: {finding.category}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}
- Parameter: {finding.affected_parameter or 'N/A'}
- PoC: {finding.proof_of_concept or 'N/A'}

REQUIREMENTS:
1. Follow HackerOne report format
2. Include:
   - Summary (2-3 sentences)
   - Vulnerability Details
   - Steps to Reproduce (numbered)
   - Impact Analysis
   - Remediation Recommendations
   - CVSS Score estimation
3. Professional tone
4. Clear and concise
5. Include severity justification

FORMAT:
- Return as Markdown
- No code fences around the entire document
- Use proper Markdown headers
"""

    def _call_claude(self, prompt: str) -> str:
        """Call Claude API and return response."""

        message = self.client.messages.create(
            model=self.model,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )

        return message.content[0].text

    def _extract_code(self, response: str, extension: str) -> str:
        """Extract code from Claude response (remove markdown fences)."""

        # Remove markdown code fences if present
        lines = response.split("\n")

        # Remove first line if it's a code fence
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]

        # Remove last line if it's a code fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        code = "\n".join(lines)

        # Ensure shebang is present
        if extension == "py" and not code.startswith("#!/"):
            code = "#!/usr/bin/env python3\n" + code
        elif extension == "sh" and not code.startswith("#!/"):
            code = "#!/bin/bash\n" + code

        return code

    def _sanitize_filename(self, title: str) -> str:
        """Sanitize title for use in filename."""

        # Remove special characters, keep alphanumeric and spaces
        safe = "".join(c if c.isalnum() or c.isspace() else "_" for c in title)

        # Replace spaces with underscores
        safe = safe.replace(" ", "_")

        # Limit length
        safe = safe[:50]

        # Remove trailing underscores
        safe = safe.strip("_")

        return safe.lower()
