"""
Finding deduplication utility.

Identifies and marks duplicate findings based on similarity analysis.
"""

from typing import List, Dict, Tuple
from difflib import SequenceMatcher
from findings.models import Finding


class FindingDeduplicator:
    """Deduplicate findings using intelligent similarity matching."""

    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize deduplicator.

        Args:
            similarity_threshold: Similarity ratio (0.0-1.0) to consider duplicates
                                 Default 0.85 = 85% similar
        """
        self.similarity_threshold = similarity_threshold

    def deduplicate_scan(self, scan_id: int) -> Dict:
        """
        Find and mark duplicates for a specific scan.

        Args:
            scan_id: Scan ID to deduplicate

        Returns:
            Dict with statistics: total, unique, duplicates, groups
        """
        # Get all findings for this scan
        findings = Finding.objects.filter(scan_id=scan_id).order_by("id")

        if not findings:
            return {"total": 0, "unique": 0, "duplicates": 0, "groups": []}

        # Group findings by similarity
        duplicate_groups = self._find_duplicate_groups(findings)

        # Mark duplicates in database
        duplicates_marked = self._mark_duplicates(duplicate_groups)

        total = findings.count()
        unique = total - duplicates_marked

        return {
            "total": total,
            "unique": unique,
            "duplicates": duplicates_marked,
            "groups": duplicate_groups,
        }

    def _find_duplicate_groups(self, findings: List[Finding]) -> List[List[int]]:
        """
        Find groups of duplicate findings.

        Args:
            findings: List of Finding objects

        Returns:
            List of duplicate groups (each group is list of finding IDs)
        """
        groups = []
        processed = set()

        findings_list = list(findings)

        for i, finding1 in enumerate(findings_list):
            if finding1.id in processed:
                continue

            # Start new group with this finding
            group = [finding1.id]

            # Compare with remaining findings
            for finding2 in findings_list[i + 1 :]:
                if finding2.id in processed:
                    continue

                # Check if duplicate
                if self._is_duplicate(finding1, finding2):
                    group.append(finding2.id)
                    processed.add(finding2.id)

            # Only add group if it has duplicates
            if len(group) > 1:
                groups.append(group)
                processed.add(finding1.id)

        return groups

    def _is_duplicate(self, finding1: Finding, finding2: Finding) -> bool:
        """
        Check if two findings are duplicates.

        Args:
            finding1: First finding
            finding2: Second finding

        Returns:
            True if duplicates, False otherwise
        """
        # Quick filters - must match
        if finding1.severity != finding2.severity:
            return False

        if finding1.category != finding2.category:
            return False

        # Compare affected URLs (if present)
        if finding1.affected_url and finding2.affected_url:
            if finding1.affected_url == finding2.affected_url:
                # Same URL - check parameter
                if finding1.affected_parameter and finding2.affected_parameter:
                    if finding1.affected_parameter == finding2.affected_parameter:
                        return True  # Same URL + same parameter = duplicate

        # Compare titles
        title_similarity = self._text_similarity(finding1.title, finding2.title)

        # Compare descriptions
        desc_similarity = self._text_similarity(
            finding1.description or "", finding2.description or ""
        )

        # Average similarity
        avg_similarity = (title_similarity + desc_similarity) / 2

        return avg_similarity >= self.similarity_threshold

    def _text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity ratio between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity ratio (0.0-1.0)
        """
        if not text1 or not text2:
            return 0.0

        # Normalize texts
        text1 = text1.lower().strip()
        text2 = text2.lower().strip()

        # Calculate similarity
        return SequenceMatcher(None, text1, text2).ratio()

    def _mark_duplicates(self, duplicate_groups: List[List[int]]) -> int:
        """
        Mark findings as duplicates in database.

        Keep the first finding in each group as original,
        mark the rest as duplicates.

        Args:
            duplicate_groups: List of duplicate groups

        Returns:
            Number of findings marked as duplicate
        """
        duplicates_marked = 0

        for group in duplicate_groups:
            if len(group) < 2:
                continue

            # First finding is the "original"
            original_id = group[0]

            # Mark rest as duplicates
            duplicate_ids = group[1:]

            for dup_id in duplicate_ids:
                finding = Finding.objects.get(id=dup_id)

                # Update status to duplicate
                finding.status = "duplicate"

                # Add note about original
                if finding.notes:
                    finding.notes += f"\n\nDuplicate of finding #{original_id}"
                else:
                    finding.notes = f"Duplicate of finding #{original_id}"

                finding.save()
                duplicates_marked += 1

        return duplicates_marked

    def get_duplicate_stats(self, scan_id: int) -> Dict:
        """
        Get duplicate statistics for a scan without modifying data.

        Args:
            scan_id: Scan ID

        Returns:
            Dict with statistics
        """
        findings = Finding.objects.filter(scan_id=scan_id)

        total = findings.count()
        already_marked = findings.filter(status="duplicate").count()

        # Find potential duplicates
        duplicate_groups = self._find_duplicate_groups(findings)
        potential_duplicates = sum(len(group) - 1 for group in duplicate_groups)

        return {
            "total": total,
            "already_marked": already_marked,
            "potential_duplicates": potential_duplicates,
            "groups": len(duplicate_groups),
        }
