"""
PoC (Proof of Concept) Generator using Claude API.

Generates executable exploit scripts and report templates for security findings.
"""

import os
import re
from pathlib import Path
from typing import Dict, Optional
from anthropic import Anthropic


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

        # Extract code from response (remove markdown fences)
        code = self._extract_code(response, extension)

        # Validate safety (skip for reports)
        try:
            self._validate_poc_safety(code, extension)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # Generate filename
        if output_path:
            file_path = Path(output_path)
        else:
            # Auto-generate filename
            safe_title = self._sanitize_filename(finding.title)
            filename = f"poc_{finding.id}_{safe_title}.{extension}"
            file_path = self.output_dir / filename

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
        """Build prompt for Python PoC generation with strict safety controls."""

        return f"""Generate a Python proof-of-concept script for this security finding:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Category: {finding.category}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}
- Affected Parameter: {finding.affected_parameter or 'N/A'}
- Tool: {finding.discovered_by or 'N/A'}

STRICT SAFETY REQUIREMENTS - MANDATORY:

1. ABSOLUTELY FORBIDDEN (NEVER INCLUDE):
   - Brute force loops (for password in passwords)
   - Multiple authentication attempts
   - Password wordlists or credential testing
   - DoS/resource exhaustion (no infinite loops, no large iterations)
   - Data destruction (no DELETE, DROP, rm -rf)
   - Automated fuzzing loops (max 3-5 manual test cases)
   - Any form of "while True" or iteration over large datasets

2. SINGLE REQUEST RULE:
   - Maximum 1 HTTP request per endpoint
   - If testing multiple inputs, use 3-5 manual examples (NOT loops)
   - NO iteration over wordlists or parameter lists

3. PASSIVE RECONNAISSANCE ONLY:
   - DNS queries are OK
   - Single HTTP GET/POST is OK
   - Header analysis is OK
   - Content inspection is OK

4. EDUCATIONAL PURPOSE:
   - Script demonstrates vulnerability EXISTS
   - NOT designed for exploitation
   - Clear TODO markers for manual testing
   - Explain each step in comments

PYTHON REQUIREMENTS:
1. Python 3.12+ compatible
2. Use requests library for HTTP
3. Include comprehensive English comments
4. Add ethical disclaimer at top
5. Print results clearly
6. Handle errors gracefully
7. Return ONLY Python code (no markdown fences)
8. Start with shebang: #!/usr/bin/env python3

RESPONSE FORMAT:
- Return ONLY the Python code
- NO markdown code fences
- Include docstring explaining vulnerability
- Maximum 200 lines of code
- Focus on DEMONSTRATION, not exploitation

Example structure:
#!/usr/bin/env python3
\"\"\"[Vulnerability explanation]\"\"\"
import requests
# [Ethical disclaimer]
# [Configuration]
# [Single test function]
# [Output results]
"""

    def _build_bash_prompt(self, finding) -> str:
        """Build prompt for Bash PoC generation with strict safety controls."""

        return f"""Generate a Bash shell script for this security finding:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}

STRICT SAFETY REQUIREMENTS - MANDATORY:

1. ABSOLUTELY FORBIDDEN (NEVER INCLUDE):
   - Brute force loops
   - Multiple authentication attempts
   - Password lists or credential testing
   - DoS attacks (no fork bombs, no resource exhaustion)
   - Data destruction commands
   - Automated fuzzing (max 3-5 manual examples)

2. SINGLE REQUEST RULE:
   - Maximum 1 curl request per endpoint
   - If multiple tests needed, use 3-5 manual examples (NOT loops)
   - NO for loops over wordlists

3. SAFE OPERATIONS ONLY:
   - curl/wget single requests OK
   - DNS queries (dig, nslookup) OK
   - Header inspection OK
   - Content analysis OK

BASH REQUIREMENTS:
1. Valid Bash syntax
2. Use curl for HTTP operations
3. Clear English comments
4. Ethical disclaimer at top
5. Print results clearly
6. Return ONLY Bash code (no markdown)
7. Start with: #!/bin/bash

RESPONSE FORMAT:
- Return ONLY the Bash code
- NO markdown code fences
- Include comments explaining vulnerability
- Maximum 100 lines
- Demonstration purpose only
"""

    def _build_curl_prompt(self, finding) -> str:
        """Build prompt for cURL command generation with strict safety controls."""

        return f"""Generate cURL commands to demonstrate this vulnerability:

FINDING DETAILS:
- Title: {finding.title}
- Severity: {finding.severity}
- Description: {finding.description}
- Affected URL: {finding.affected_url or 'N/A'}
- Parameter: {finding.affected_parameter or 'N/A'}

STRICT SAFETY REQUIREMENTS - MANDATORY:

1. ABSOLUTELY FORBIDDEN:
   - NO brute force attempts
   - NO authentication loops
   - NO password testing
   - NO destructive operations
   - NO DoS attempts

2. COMMAND LIMITS:
   - Maximum 3-5 cURL commands total
   - Each command runs ONCE (no loops)
   - Single request per endpoint
   - Demonstrate vulnerability only

3. SAFE TESTING:
   - Single HTTP requests OK
   - Header inspection OK
   - Parameter testing with 2-3 examples max
   - Show expected responses

REQUIREMENTS:
1. Provide 3-5 cURL commands maximum
2. Include comments explaining each command
3. Show expected responses
4. Include ethical disclaimer
5. Make commands copy-paste ready

FORMAT:
- Return as shell script with cURL commands
- NO markdown code fences
- Start with #!/bin/bash
- Educational purpose only
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

REPORT REQUIREMENTS:

1. Follow HackerOne report format
2. Include:
   - Summary (2-3 sentences)
   - Vulnerability Details
   - Steps to Reproduce (numbered, specific)
   - Impact Analysis (business and technical)
   - Remediation Recommendations
   - CVSS Score estimation with justification

3. Professional tone
4. Clear and concise
5. Include severity justification
6. Focus on business impact

FORMAT:
- Return as Markdown
- NO code fences around entire document
- Use proper Markdown headers (##)
- Include all required sections
- Maximum 500 lines

Note: This is a report template, not executable code.
No safety restrictions needed for report format.
"""

    def _call_claude(self, prompt: str) -> str:
        """Call Claude API and return response."""
        message = self.client.messages.create(
            model=self.model,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    def _validate_poc_safety(self, code: str, extension: str) -> bool:
        """
        Validate that generated PoC doesn't contain dangerous patterns.

        Args:
            code: Generated PoC code
            extension: File extension (py, sh, md)

        Returns:
            True if safe, raises ValueError if dangerous

        Raises:
            ValueError: If dangerous pattern detected
        """
        # Skip validation for reports (markdown)
        if extension == 'md':
            return True

        # Dangerous patterns that should NEVER appear in PoCs
        dangerous_patterns = {
            r'for\s+\w+\s+in\s+.*password': 'Password brute force loop detected',
            r'while\s+True': 'Infinite loop detected',
            r'range\s*\(\s*[1-9]\d{2,}': 'Large iteration loop detected (100+ iterations)',
            r'hydra|medusa|john': 'Brute force tool reference detected',
            r'rm\s+-rf|DROP\s+TABLE|DELETE\s+FROM': 'Destructive operation detected',
            r'for\s+\w+\s+in\s+.*wordlist': 'Wordlist iteration detected',
            r'&\s*$|;\s*$.*&': 'Background process/fork bomb pattern',
            r':\(\)\{.*:\|:': 'Fork bomb detected',
            r'curl.*--data.*password.*for': 'Authentication brute force detected',
        }

        # Check each pattern
        for pattern, error_msg in dangerous_patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                raise ValueError(
                    f"UNSAFE PoC DETECTED: {error_msg}\n"
                    f"Pattern: {pattern}\n"
                    f"This violates bug bounty ethics and could be illegal.\n"
                    f"PoC generation aborted for safety."
                )

        # Count HTTP requests (should be minimal)
        http_request_count = len(re.findall(r'requests\.(get|post|put|delete|patch)', code, re.IGNORECASE))
        http_request_count += len(re.findall(r'curl\s+', code, re.IGNORECASE))

        if http_request_count > 10:
            raise ValueError(
                f"Too many HTTP requests detected ({http_request_count}).\n"
                f"PoC should demonstrate vulnerability with minimal requests (max 10).\n"
                f"This may constitute automated scanning or DoS."
            )

        return True

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
