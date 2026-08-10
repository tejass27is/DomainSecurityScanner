"""
Weighted Scoring System for Domain Security

This module implements a transparent, multi-factor scoring system that considers:
- Category-specific vulnerability weights
- Domain criticality levels
- Compliance requirements
- Industry standards
"""

from enum import Enum
from typing import Dict, Tuple, List
from dataclasses import dataclass


class DomainCriticality(str, Enum):
    """Domain criticality levels affecting score multiplier"""
    CRITICAL = "critical"  # Financial, Healthcare, Government: 1.5x
    HIGH = "high"  # E-commerce, Payment processors: 1.3x
    MEDIUM = "medium"  # Standard business: 1.0x
    LOW = "low"  # Informational, blogs: 0.8x


# Category weights (must sum to 1.0)
CATEGORY_WEIGHTS = {
    "TLS Security": 0.35,  # Encryption is critical
    "DNS Security": 0.25,  # Data integrity & delivery
    "Mail Security": 0.15,  # Email security
    "Network Security": 0.15,  # Access control
    "Application Security": 0.10,  # Often fixable
}

# Domain criticality multipliers (applies to final score)
CRITICALITY_MULTIPLIERS = {
    DomainCriticality.CRITICAL.value: 1.5,
    DomainCriticality.HIGH.value: 1.3,
    DomainCriticality.MEDIUM.value: 1.0,
    DomainCriticality.LOW.value: 0.8,
}

# Severity penalty mapping (lower is worse)
SEVERITY_PENALTY = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}


@dataclass
class CategoryScore:
    """Score breakdown for a single category"""
    category: str
    raw_score: int  # 0-100
    weighted_score: float  # After applying weight
    weight: float
    vulnerabilities_count: int
    critical_count: int
    high_count: int


@dataclass
class ScoringBreakdown:
    """Complete scoring breakdown with transparency"""
    total_score: float  # Final score after all calculations
    base_score: float  # Before criticality adjustment
    category_scores: List[CategoryScore]
    criticality_level: str
    criticality_multiplier: float
    compliance_scores: Dict[str, float]  # PCI, SOC2, GDPR


def calculate_category_score(findings: Dict) -> Tuple[int, int, int, int]:
    """
    Calculate score for a category based on findings.
    
    Args:
        findings: Dict with vulnerability rules and their severity/count
        
    Returns:
        Tuple: (raw_score, critical_count, high_count, total_vulns)
    """
    if not findings or not isinstance(findings, dict):
        return 100, 0, 0, 0

    penalty = 0
    critical_count = 0
    high_count = 0
    total_vulns = 0

    for rule_name, hosts in findings.items():
        if not isinstance(hosts, list):
            continue

        for host in hosts:
            total_vulns += 1
            severity = (host.get("severity") or "info").lower()

            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1

            penalty += SEVERITY_PENALTY.get(severity, 1)

    # Calculate raw score (0-100)
    raw_score = max(0, 100 - penalty)
    return raw_score, critical_count, high_count, total_vulns


def calculate_weighted_score(
    categories: Dict[str, Dict],
    criticality_level: str = DomainCriticality.MEDIUM.value,
    ip_reputation_score: int = None,
) -> ScoringBreakdown:
    """
    Calculate final weighted score with complete breakdown.
    
    Args:
        categories: Dict of category_name -> findings
        criticality_level: One of CRITICAL, HIGH, MEDIUM, LOW
        ip_reputation_score: Optional IP reputation score (0-100)
        
    Returns:
        ScoringBreakdown object with detailed scoring information
    """
    
    category_scores = []
    weighted_sum = 0.0
    weight_total = 0.0

    # Calculate scores for each category
    for category, findings in categories.items():
        weight = CATEGORY_WEIGHTS.get(category, 0)
        if weight == 0:
            continue

        raw_score, crit_count, high_count, total_vulns = calculate_category_score(findings)
        weighted_score = raw_score * weight

        category_scores.append(
            CategoryScore(
                category=category,
                raw_score=raw_score,
                weighted_score=weighted_score,
                weight=weight,
                vulnerabilities_count=total_vulns,
                critical_count=crit_count,
                high_count=high_count,
            )
        )

        weighted_sum += weighted_score
        weight_total += weight

    # Calculate base score (average of all categories)
    base_score = weighted_sum / weight_total if weight_total > 0 else 100

    # Apply IP reputation penalty if available
    if ip_reputation_score is not None and ip_reputation_score > 50:
        reputation_penalty = (ip_reputation_score - 50) * 0.1  # Max 5 points
        base_score = max(0, base_score - reputation_penalty)

    # Apply criticality multiplier
    multiplier = CRITICALITY_MULTIPLIERS.get(criticality_level, 1.0)
    final_score = (base_score * multiplier) / (1 if multiplier >= 1 else 1)
    # Cap at 100 for scores that improve due to low criticality
    final_score = min(100, max(0, final_score))

    # Calculate compliance scores
    compliance_scores = calculate_compliance_scores(category_scores, criticality_level)

    return ScoringBreakdown(
        total_score=round(final_score, 2),
        base_score=round(base_score, 2),
        category_scores=category_scores,
        criticality_level=criticality_level,
        criticality_multiplier=multiplier,
        compliance_scores=compliance_scores,
    )


def calculate_compliance_scores(
    category_scores: List[CategoryScore],
    criticality_level: str
) -> Dict[str, float]:
    """
    Calculate compliance readiness scores for various standards.
    
    Args:
        category_scores: List of CategoryScore objects
        criticality_level: Domain criticality level
        
    Returns:
        Dict with compliance scores (0-100 for each standard)
    """
    
    # Find individual category scores
    scores_map = {cs.category: cs.raw_score for cs in category_scores}
    
    tls_score = scores_map.get("TLS Security", 50)
    dns_score = scores_map.get("DNS Security", 50)
    network_score = scores_map.get("Network Security", 50)
    app_score = scores_map.get("Application Security", 50)
    mail_score = scores_map.get("Mail Security", 50)

    # PCI-DSS: Requires strong encryption, secure network
    pci_score = (tls_score * 0.4 + network_score * 0.3 + app_score * 0.3)

    # SOC2: Requires all categories
    soc2_score = (tls_score * 0.25 + dns_score * 0.25 + network_score * 0.25 + app_score * 0.25)

    # GDPR: Focus on encryption and security headers
    gdpr_score = (tls_score * 0.5 + app_score * 0.5)

    # Apply strictness multiplier for critical domains
    if criticality_level == "critical":
        threshold = 85
    elif criticality_level == "high":
        threshold = 80
    else:
        threshold = 75

    return {
        "PCI-DSS": round(min(100, pci_score), 2),
        "SOC2": round(min(100, soc2_score), 2),
        "GDPR": round(min(100, gdpr_score), 2),
        "CIS-Benchmarks": round(min(100, app_score * 0.7 + network_score * 0.3), 2),
    }


def get_criticality_from_domain_keywords(domain: str) -> str:
    """
    Auto-detect criticality level based on domain keywords.
    Fallback for when admin hasn't manually set criticality.
    
    Args:
        domain: Domain name
        
    Returns:
        Criticality level string
    """
    domain_lower = domain.lower()

    # Critical keywords
    critical_keywords = ["bank", "payment", "finance", "hospital", "health", "insurance", "government"]
    if any(kw in domain_lower for kw in critical_keywords):
        return DomainCriticality.CRITICAL.value

    # High keywords
    high_keywords = ["shop", "store", "ecommerce", "cart", "checkout", "paypal"]
    if any(kw in domain_lower for kw in high_keywords):
        return DomainCriticality.HIGH.value

    # Low keywords
    low_keywords = ["blog", "news", "wiki", "forum", "community"]
    if any(kw in domain_lower for kw in low_keywords):
        return DomainCriticality.LOW.value

    return DomainCriticality.MEDIUM.value


def format_scoring_response(breakdown: ScoringBreakdown) -> Dict:
    """
    Format scoring breakdown for API response.
    
    Args:
        breakdown: ScoringBreakdown object
        
    Returns:
        Dict formatted for JSON response
    """
    return {
        "total_score": breakdown.total_score,
        "base_score": breakdown.base_score,
        "scoring_breakdown": {
            "categories": [
                {
                    "name": cs.category,
                    "raw_score": cs.raw_score,
                    "weighted_score": round(cs.weighted_score, 2),
                    "weight": cs.weight,
                    "vulnerabilities": {
                        "critical": cs.critical_count,
                        "high": cs.high_count,
                        "total": cs.vulnerabilities_count,
                    },
                }
                for cs in breakdown.category_scores
            ],
            "criticality": {
                "level": breakdown.criticality_level,
                "multiplier": breakdown.criticality_multiplier,
                "description": get_criticality_description(breakdown.criticality_level),
            },
        },
        "compliance": {
            "scores": breakdown.compliance_scores,
            "status": get_compliance_status(breakdown.compliance_scores),
        },
    }


def get_criticality_description(level: str) -> str:
    """Get human-readable description for criticality level."""
    descriptions = {
        "critical": "Processes sensitive data (finance, healthcare, government)",
        "high": "E-commerce, payment processing, or customer-facing systems",
        "medium": "Standard business systems",
        "low": "Informational, non-critical services",
    }
    return descriptions.get(level, "Unknown")


def get_compliance_status(compliance_scores: Dict[str, float]) -> Dict[str, str]:
    """
    Determine compliance readiness status.
    
    Returns:
        Dict with status for each compliance standard
    """
    def score_to_status(score: float) -> str:
        if score >= 85:
            return "READY"
        elif score >= 70:
            return "IN_PROGRESS"
        else:
            return "NOT_READY"

    return {key: score_to_status(val) for key, val in compliance_scores.items()}

"""
Weighted Scoring System for Domain Security

This module implements a transparent, multi-factor scoring system that considers:
- Category-specific vulnerability weights
- Domain criticality levels
- Compliance requirements
- Industry standards
"""

from enum import Enum
from typing import Dict, Tuple, List
from dataclasses import dataclass


class DomainCriticality(str, Enum):
    """Domain criticality levels affecting score multiplier"""
    CRITICAL = "critical"  # Financial, Healthcare, Government: 1.5x
    HIGH = "high"  # E-commerce, Payment processors: 1.3x
    MEDIUM = "medium"  # Standard business: 1.0x
    LOW = "low"  # Informational, blogs: 0.8x


# Category weights (must sum to 1.0)
CATEGORY_WEIGHTS = {
    "TLS Security": 0.35,  # Encryption is critical
    "DNS Security": 0.25,  # Data integrity & delivery
    "Mail Security": 0.15,  # Email security
    "Network Security": 0.15,  # Access control
    "Application Security": 0.10,  # Often fixable
}

# Domain criticality multipliers (applies to final score)
CRITICALITY_MULTIPLIERS = {
    DomainCriticality.CRITICAL.value: 1.5,
    DomainCriticality.HIGH.value: 1.3,
    DomainCriticality.MEDIUM.value: 1.0,
    DomainCriticality.LOW.value: 0.8,
}

# Severity penalty mapping (lower is worse)
SEVERITY_PENALTY = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 1,
}


@dataclass
class CategoryScore:
    """Score breakdown for a single category"""
    category: str
    raw_score: int  # 0-100
    weighted_score: float  # After applying weight
    weight: float
    vulnerabilities_count: int
    critical_count: int
    high_count: int


@dataclass
class ScoringBreakdown:
    """Complete scoring breakdown with transparency"""
    total_score: float  # Final score after all calculations
    base_score: float  # Before criticality adjustment
    category_scores: List[CategoryScore]
    criticality_level: str
    criticality_multiplier: float
    compliance_scores: Dict[str, float]  # PCI, SOC2, GDPR


def calculate_category_score(findings: Dict) -> Tuple[int, int, int, int]:
    """
    Calculate score for a category based on findings.
    
    Args:
        findings: Dict with vulnerability rules and their severity/count
        
    Returns:
        Tuple: (raw_score, critical_count, high_count, total_vulns)
    """
    if not findings or not isinstance(findings, dict):
        return 100, 0, 0, 0

    penalty = 0.0
    critical_count = 0
    high_count = 0
    total_vulns = 0

    for rule_name, hosts in findings.items():
        if not isinstance(hosts, list) or not hosts:
            continue

        # Use the dominant severity within a rule so the rule contributes once
        severities = [
            (host.get("severity") or "info").lower()
            for host in hosts
            if isinstance(host, dict)
        ]
        dominant = next(
            (s for s in ("critical", "high", "medium", "low", "info") if s in severities),
            "info",
        )

        host_count = len(hosts)
        total_vulns += host_count
        for host in hosts:
            if not isinstance(host, dict):
                continue
            severity = (host.get("severity") or "info").lower()
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1

        # Diminishing returns for affected hosts — the same rule across many
        # subdomains shouldn't zero out the whole category score.
        host_factor = 1 + min((host_count - 1) * 0.35, 2.4)
        penalty += SEVERITY_PENALTY.get(dominant, 1) * host_factor

    # Floor the penalty so a category with findings never reads as 0
    penalty = min(penalty, 85)
    raw_score = max(15, round(100 - penalty))
    return raw_score, critical_count, high_count, total_vulns


def calculate_weighted_score(
    categories: Dict[str, Dict],
    criticality_level: str = DomainCriticality.MEDIUM.value,
    ip_reputation_score: int = None,
) -> ScoringBreakdown:
    """
    Calculate final weighted score with complete breakdown.
    
    Args:
        categories: Dict of category_name -> findings
        criticality_level: One of CRITICAL, HIGH, MEDIUM, LOW
        ip_reputation_score: Optional IP reputation score (0-100)
        
    Returns:
        ScoringBreakdown object with detailed scoring information
    """
    
    category_scores = []
    weighted_sum = 0.0
    weight_total = 0.0

    # Calculate scores for each category
    for category, findings in categories.items():
        weight = CATEGORY_WEIGHTS.get(category, 0)
        if weight == 0:
            continue

        raw_score, crit_count, high_count, total_vulns = calculate_category_score(findings)
        weighted_score = raw_score * weight

        category_scores.append(
            CategoryScore(
                category=category,
                raw_score=raw_score,
                weighted_score=weighted_score,
                weight=weight,
                vulnerabilities_count=total_vulns,
                critical_count=crit_count,
                high_count=high_count,
            )
        )

        weighted_sum += weighted_score
        weight_total += weight

    # Calculate base score (average of all categories)
    base_score = weighted_sum / weight_total if weight_total > 0 else 100

    # Apply IP reputation penalty if available
    if ip_reputation_score is not None and ip_reputation_score > 50:
        reputation_penalty = (ip_reputation_score - 50) * 0.1  # Max 5 points
        base_score = max(0, base_score - reputation_penalty)

    # Apply criticality multiplier
    multiplier = CRITICALITY_MULTIPLIERS.get(criticality_level, 1.0)
    final_score = (base_score * multiplier) / (1 if multiplier >= 1 else 1)
    # Cap at 100 for scores that improve due to low criticality
    final_score = min(100, max(0, final_score))

    # Calculate compliance scores
    compliance_scores = calculate_compliance_scores(category_scores, criticality_level)

    return ScoringBreakdown(
        total_score=round(final_score, 2),
        base_score=round(base_score, 2),
        category_scores=category_scores,
        criticality_level=criticality_level,
        criticality_multiplier=multiplier,
        compliance_scores=compliance_scores,
    )


def calculate_compliance_scores(
    category_scores: List[CategoryScore],
    criticality_level: str
) -> Dict[str, float]:
    """
    Calculate compliance readiness scores for various standards.
    
    Args:
        category_scores: List of CategoryScore objects
        criticality_level: Domain criticality level
        
    Returns:
        Dict with compliance scores (0-100 for each standard)
    """
    
    # Find individual category scores
    scores_map = {cs.category: cs.raw_score for cs in category_scores}
    
    tls_score = scores_map.get("TLS Security", 50)
    dns_score = scores_map.get("DNS Security", 50)
    network_score = scores_map.get("Network Security", 50)
    app_score = scores_map.get("Application Security", 50)
    mail_score = scores_map.get("Mail Security", 50)

    # PCI-DSS: Requires strong encryption, secure network
    pci_score = (tls_score * 0.4 + network_score * 0.3 + app_score * 0.3)

    # SOC2: Requires all categories
    soc2_score = (tls_score * 0.25 + dns_score * 0.25 + network_score * 0.25 + app_score * 0.25)

    # GDPR: Focus on encryption and security headers
    gdpr_score = (tls_score * 0.5 + app_score * 0.5)

    # Apply strictness multiplier for critical domains
    if criticality_level == "critical":
        threshold = 85
    elif criticality_level == "high":
        threshold = 80
    else:
        threshold = 75

    return {
        "PCI-DSS": round(min(100, pci_score), 2),
        "SOC2": round(min(100, soc2_score), 2),
        "GDPR": round(min(100, gdpr_score), 2),
        "CIS-Benchmarks": round(min(100, app_score * 0.7 + network_score * 0.3), 2),
    }


def get_criticality_from_domain_keywords(domain: str) -> str:
    """
    Auto-detect criticality level based on domain keywords.
    Fallback for when admin hasn't manually set criticality.
    
    Args:
        domain: Domain name
        
    Returns:
        Criticality level string
    """
    domain_lower = domain.lower()

    # Critical keywords
    critical_keywords = ["bank", "payment", "finance", "hospital", "health", "insurance", "government"]
    if any(kw in domain_lower for kw in critical_keywords):
        return DomainCriticality.CRITICAL.value

    # High keywords
    high_keywords = ["shop", "store", "ecommerce", "cart", "checkout", "paypal"]
    if any(kw in domain_lower for kw in high_keywords):
        return DomainCriticality.HIGH.value

    # Low keywords
    low_keywords = ["blog", "news", "wiki", "forum", "community"]
    if any(kw in domain_lower for kw in low_keywords):
        return DomainCriticality.LOW.value

    return DomainCriticality.MEDIUM.value


def format_scoring_response(breakdown: ScoringBreakdown) -> Dict:
    """
    Format scoring breakdown for API response.
    
    Args:
        breakdown: ScoringBreakdown object
        
    Returns:
        Dict formatted for JSON response
    """
    return {
        "total_score": breakdown.total_score,
        "base_score": breakdown.base_score,
        "scoring_breakdown": {
            "categories": [
                {
                    "name": cs.category,
                    "raw_score": cs.raw_score,
                    "weighted_score": round(cs.weighted_score, 2),
                    "weight": cs.weight,
                    "vulnerabilities": {
                        "critical": cs.critical_count,
                        "high": cs.high_count,
                        "total": cs.vulnerabilities_count,
                    },
                }
                for cs in breakdown.category_scores
            ],
            "criticality": {
                "level": breakdown.criticality_level,
                "multiplier": breakdown.criticality_multiplier,
                "description": get_criticality_description(breakdown.criticality_level),
            },
        },
        "compliance": {
            "scores": breakdown.compliance_scores,
            "status": get_compliance_status(breakdown.compliance_scores),
        },
    }


def get_criticality_description(level: str) -> str:
    """Get human-readable description for criticality level."""
    descriptions = {
        "critical": "Processes sensitive data (finance, healthcare, government)",
        "high": "E-commerce, payment processing, or customer-facing systems",
        "medium": "Standard business systems",
        "low": "Informational, non-critical services",
    }
    return descriptions.get(level, "Unknown")


def get_compliance_status(compliance_scores: Dict[str, float]) -> Dict[str, str]:
    """
    Determine compliance readiness status.
    
    Returns:
        Dict with status for each compliance standard
    """
    def score_to_status(score: float) -> str:
        if score >= 85:
            return "READY"
        elif score >= 70:
            return "IN_PROGRESS"
        else:
            return "NOT_READY"

    return {key: score_to_status(val) for key, val in compliance_scores.items()}
