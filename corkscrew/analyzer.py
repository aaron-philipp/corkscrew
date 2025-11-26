"""Core analysis engine for detecting synthetic/honeypot Terraform configurations."""
import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any
from collections import Counter

import hcl2


@dataclass
class Flag:
    """A specific detection flag that was triggered."""
    category: str
    name: str
    severity: float  # 0-1, contribution to synthetic score
    description: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class CategoryScore:
    """Score breakdown for a detection category."""
    name: str
    score: float  # 0-100
    max_score: float
    flags: list[Flag] = field(default_factory=list)

    @property
    def normalized_score(self) -> float:
        return (self.score / self.max_score * 100) if self.max_score > 0 else 0


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    synthetic_score: float  # 0-100, higher = more likely synthetic
    confidence: str  # low, medium, high
    categories: list[CategoryScore] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "synthetic_score": round(self.synthetic_score, 1),
            "confidence": self.confidence,
            "verdict": self._get_verdict(),
            "categories": [
                {
                    "name": cat.name,
                    "score": round(cat.normalized_score, 1),
                    "flags": [
                        {
                            "name": f.name,
                            "severity": f.severity,
                            "description": f.description,
                            "evidence": f.evidence[:5]  # Limit evidence shown
                        }
                        for f in cat.flags
                    ]
                }
                for cat in self.categories
            ],
            "summary": self.summary
        }

    def _get_verdict(self) -> str:
        if self.synthetic_score >= 75:
            return "HIGHLY LIKELY SYNTHETIC/HONEYPOT"
        elif self.synthetic_score >= 50:
            return "PROBABLE SYNTHETIC"
        elif self.synthetic_score >= 30:
            return "SUSPICIOUS - MIXED SIGNALS"
        else:
            return "LIKELY ORGANIC"


class TerraformAnalyzer:
    """Analyzes Terraform configurations for synthetic/honeypot indicators."""

    # Patterns that suggest organic infrastructure
    ORGANIC_NAME_PATTERNS = [
        r'old[-_]',
        r'legacy[-_]',
        r'test[-_]?(?!ing)',
        r'temp[-_]',
        r'tmp[-_]',
        r'backup[-_]',
        r'bak[-_]',
        r'deprecated',
        r'dont[-_]?delete',
        r'do[-_]?not[-_]?delete',
        r'keep',
        r'wip[-_]',
        r'fixme',
        r'todo',
        r'hack',
        r'workaround',
        r'\d{6,}',  # Long numbers often indicate dates/tickets
        r'v\d+[-_]',  # Version prefixes
    ]

    # Patterns that suggest synthetic/formulaic naming
    SYNTHETIC_NAME_PATTERNS = [
        r'^(web|app|db|cache|api|worker)[-_]server[-_]\d+$',
        r'^(web|app|db|cache|api|worker)[-_]\d+$',
        r'^server[-_]\d+$',
        r'^instance[-_]\d+$',
        r'^node[-_]\d+$',
    ]

    # Ticket reference patterns (organic signal)
    TICKET_PATTERNS = [
        r'[A-Z]{2,10}[-_]\d{3,6}',  # JIRA-1234, PROJ-12345
        r'#\d{4,}',  # GitHub issue style
        r'ticket[-_]?\d+',
        r'issue[-_]?\d+',
        r'bug[-_]?\d+',
    ]

    def __init__(self):
        self.resources: dict[str, list[dict]] = {}
        self.variables: dict = {}
        self.locals: dict = {}
        self.all_names: list[str] = []
        self.all_tags: list[dict] = []
        self.raw_content: str = ""
        self.files_parsed: int = 0

    def parse_directory(self, path: Path) -> None:
        """Parse all .tf files in a directory."""
        tf_files = list(path.glob("**/*.tf"))
        if not tf_files:
            raise ValueError(f"No .tf files found in {path}")

        for tf_file in tf_files:
            self._parse_file(tf_file)

    def parse_file(self, path: Path) -> None:
        """Parse a single .tf file."""
        self._parse_file(path)

    def _parse_file(self, path: Path) -> None:
        """Internal method to parse a Terraform file."""
        content = path.read_text(encoding='utf-8')
        self.raw_content += content + "\n"
        self.files_parsed += 1

        try:
            parsed = hcl2.loads(content)
        except Exception as e:
            raise ValueError(f"Failed to parse {path}: {e}")

        # Extract resources
        for resource in parsed.get("resource", []):
            for resource_type, instances in resource.items():
                if resource_type not in self.resources:
                    self.resources[resource_type] = []
                for name, config in instances.items():
                    self.resources[resource_type].append({
                        "name": name,
                        "config": config
                    })
                    self.all_names.append(name)
                    # Extract tags
                    if isinstance(config, dict) and "tags" in config:
                        self.all_tags.append(config["tags"])

        # Extract variables
        for var in parsed.get("variable", []):
            self.variables.update(var)

        # Extract locals
        for local in parsed.get("locals", []):
            self.locals.update(local)

    def analyze(self) -> AnalysisResult:
        """Run full analysis and return results."""
        categories = [
            self._analyze_naming_patterns(),
            self._analyze_resource_symmetry(),
            self._analyze_temporal_indicators(),
            self._analyze_structural_realism(),
            self._analyze_configuration_entropy(),
            self._analyze_organic_signals(),
            self._analyze_code_artifacts(),
        ]

        # Calculate weighted overall score
        total_score = 0
        total_weight = 0
        weights = {
            "Naming Patterns": 1.5,
            "Resource Symmetry": 1.2,
            "Temporal Indicators": 1.3,
            "Structural Realism": 1.3,
            "Configuration Entropy": 1.0,
            "Organic Signals": 1.4,
            "Code Artifacts": 0.8,
        }

        for cat in categories:
            weight = weights.get(cat.name, 1.0)
            total_score += cat.normalized_score * weight
            total_weight += weight * 100

        synthetic_score = (total_score / total_weight) * 100 if total_weight > 0 else 0

        # Determine confidence based on amount of data
        resource_count = sum(len(r) for r in self.resources.values())
        if resource_count < 5:
            confidence = "low"
        elif resource_count < 15:
            confidence = "medium"
        else:
            confidence = "high"

        result = AnalysisResult(
            synthetic_score=synthetic_score,
            confidence=confidence,
            categories=categories,
        )
        result.summary = self._generate_summary(result)

        return result

    def _analyze_naming_patterns(self) -> CategoryScore:
        """Analyze resource naming for synthetic patterns."""
        flags = []
        score = 0
        max_score = 100

        if not self.all_names:
            return CategoryScore("Naming Patterns", 0, max_score, flags)

        # Check for sequential/formulaic naming
        sequential_patterns = []
        for pattern in self.SYNTHETIC_NAME_PATTERNS:
            matches = [n for n in self.all_names if re.match(pattern, n, re.IGNORECASE)]
            if len(matches) >= 2:
                sequential_patterns.extend(matches)

        if sequential_patterns:
            severity = min(len(sequential_patterns) / len(self.all_names), 1.0)
            flags.append(Flag(
                category="Naming Patterns",
                name="Sequential/Formulaic Naming",
                severity=severity,
                description="Resources follow predictable sequential naming patterns",
                evidence=sequential_patterns[:10]
            ))
            score += severity * 30

        # Check for too-perfect naming consistency
        name_formats = self._extract_name_formats()
        if len(name_formats) == 1 and len(self.all_names) > 5:
            flags.append(Flag(
                category="Naming Patterns",
                name="Uniform Naming Convention",
                severity=0.7,
                description="All resources follow exact same naming pattern - organic infra has variation",
                evidence=[f"Pattern: {list(name_formats.keys())[0]}", f"Applied to {len(self.all_names)} resources"]
            ))
            score += 25

        # Check for missing organic naming artifacts
        has_organic_names = any(
            any(re.search(pattern, name, re.IGNORECASE) for pattern in self.ORGANIC_NAME_PATTERNS)
            for name in self.all_names
        )

        if not has_organic_names and len(self.all_names) > 3:
            flags.append(Flag(
                category="Naming Patterns",
                name="Missing Legacy/Organic Names",
                severity=0.6,
                description="No evidence of legacy resources, temp files, or organic naming chaos",
                evidence=["No 'old-*', 'legacy-*', 'temp-*', 'test-*' patterns found"]
            ))
            score += 25

        # Check for typos/inconsistencies (organic signal)
        has_inconsistencies = self._check_naming_inconsistencies()
        if not has_inconsistencies and len(self.all_names) > 5:
            flags.append(Flag(
                category="Naming Patterns",
                name="No Naming Inconsistencies",
                severity=0.4,
                description="Perfect naming consistency - real infrastructure has typos and variations",
                evidence=["All names follow consistent patterns with no deviations"]
            ))
            score += 20

        return CategoryScore("Naming Patterns", min(score, max_score), max_score, flags)

    def _analyze_resource_symmetry(self) -> CategoryScore:
        """Analyze resource distribution for unnatural symmetry."""
        flags = []
        score = 0
        max_score = 100

        # Check subnet configurations
        subnets = self.resources.get("aws_subnet", [])
        if len(subnets) >= 2:
            cidr_blocks = [s["config"].get("cidr_block", "") for s in subnets if isinstance(s["config"], dict)]

            # Check for perfect CIDR allocation
            cidr_sizes = [self._get_cidr_size(c) for c in cidr_blocks if c]
            if cidr_sizes and len(set(cidr_sizes)) == 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Uniform Subnet Sizing",
                    severity=0.5,
                    description="All subnets have identical CIDR sizes - organic networks have varied sizing",
                    evidence=[f"All subnets are /{cidr_sizes[0]}"]
                ))
                score += 20

            # Check for sequential CIDR blocks
            if self._cidrs_are_sequential(cidr_blocks):
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Sequential CIDR Allocation",
                    severity=0.6,
                    description="CIDR blocks are perfectly sequential with no gaps",
                    evidence=cidr_blocks[:5]
                ))
                score += 25

        # Check security group symmetry
        sgs = self.resources.get("aws_security_group", [])
        if len(sgs) >= 2:
            rule_counts = []
            for sg in sgs:
                config = sg["config"]
                if isinstance(config, dict):
                    ingress = len(config.get("ingress", []))
                    egress = len(config.get("egress", []))
                    rule_counts.append((ingress, egress))

            if rule_counts and len(set(rule_counts)) == 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Identical Security Group Structure",
                    severity=0.6,
                    description="All security groups have identical rule counts - organic SGs accumulate exceptions",
                    evidence=[f"All SGs have {rule_counts[0][0]} ingress, {rule_counts[0][1]} egress rules"]
                ))
                score += 25

        # Check instance type distribution
        instances = self.resources.get("aws_instance", [])
        if len(instances) >= 3:
            instance_types = [i["config"].get("instance_type", "") for i in instances if isinstance(i["config"], dict)]
            if len(set(instance_types)) == 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Uniform Instance Types",
                    severity=0.5,
                    description="All instances use identical instance type - organic environments are heterogeneous",
                    evidence=[f"All instances are {instance_types[0]}"]
                ))
                score += 20

        # Check AZ distribution
        az_resources = []
        for resource_type, resources in self.resources.items():
            for r in resources:
                if isinstance(r["config"], dict):
                    az = r["config"].get("availability_zone", "")
                    if az:
                        az_resources.append(az)

        if az_resources:
            az_counts = Counter(az_resources)
            if len(set(az_counts.values())) == 1 and len(az_counts) > 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Perfect AZ Balance",
                    severity=0.4,
                    description="Resources perfectly balanced across AZs - organic deployment drifts",
                    evidence=[f"{az}: {count}" for az, count in az_counts.items()]
                ))
                score += 15

        return CategoryScore("Resource Symmetry", min(score, max_score), max_score, flags)

    def _analyze_temporal_indicators(self) -> CategoryScore:
        """Analyze temporal patterns that suggest synthetic infrastructure."""
        flags = []
        score = 0
        max_score = 100

        # Check for timestamp patterns in names/tags that suggest batch creation
        timestamp_patterns = [
            r'20\d{2}[-_]?\d{2}[-_]?\d{2}',  # Date patterns like 2024-01-15 or 20240115
            r'\d{10,13}',  # Unix timestamps (seconds or milliseconds)
        ]

        timestamp_evidence = []
        for pattern in timestamp_patterns:
            matches = re.findall(pattern, self.raw_content)
            if matches:
                # Check if all timestamps are very similar (within same day/hour)
                timestamp_evidence.extend(matches[:5])

        # Check for identical timestamps suggesting batch creation
        if timestamp_evidence:
            unique_timestamps = set(timestamp_evidence)
            if len(unique_timestamps) == 1 and len(timestamp_evidence) > 2:
                flags.append(Flag(
                    category="Temporal Indicators",
                    name="Identical Timestamps",
                    severity=0.7,
                    description="All resources have identical timestamps - suggests batch creation",
                    evidence=[f"Repeated timestamp: {list(unique_timestamps)[0]}"]
                ))
                score += 30

        # Check for version indicators suggesting iteration
        version_patterns = [
            r'[-_]v\d+[-_]?',
            r'[-_]rev\d+',
            r'[-_]r\d+[-_]',
        ]
        has_versions = any(
            re.search(pattern, self.raw_content, re.IGNORECASE)
            for pattern in version_patterns
        )

        if not has_versions and len(self.all_names) > 5:
            flags.append(Flag(
                category="Temporal Indicators",
                name="No Version Indicators",
                severity=0.4,
                description="No version suffixes found - organic infra shows iterative changes",
                evidence=["No '-v1', '-v2', '-rev1' patterns in resource names"]
            ))
            score += 20

        # Check for deprecated/superseded resources (organic signal)
        deprecated_patterns = [
            r'deprecated',
            r'old[-_]',
            r'legacy[-_]',
            r'[-_]backup',
            r'[-_]bak',
            r'superseded',
            r'replaced',
        ]
        has_deprecated = any(
            re.search(pattern, self.raw_content, re.IGNORECASE)
            for pattern in deprecated_patterns
        )

        if not has_deprecated and len(self.all_names) > 5:
            flags.append(Flag(
                category="Temporal Indicators",
                name="No Lifecycle Cruft",
                severity=0.5,
                description="No deprecated or backup resources - organic infra keeps old resources 'just in case'",
                evidence=["No 'deprecated', 'old-', 'legacy-', '-backup' resources found"]
            ))
            score += 25

        # Check for terraform state artifacts that suggest fresh creation
        # Look for resource addresses that suggest no refactoring history
        moved_blocks = re.findall(r'moved\s*\{', self.raw_content)
        import_blocks = re.findall(r'import\s*\{', self.raw_content)

        if not moved_blocks and not import_blocks and len(self.resources) > 10:
            flags.append(Flag(
                category="Temporal Indicators",
                name="No Resource Migrations",
                severity=0.3,
                description="No moved/import blocks - long-lived infra typically has refactoring artifacts",
                evidence=["No moved {} or import {} blocks found"]
            ))
            score += 15

        # Check for creation timestamp in tags
        creation_tags = ['CreatedAt', 'CreatedOn', 'CreateDate', 'created_at', 'created_on']
        has_creation_tags = any(
            any(tag in str(t) for tag in creation_tags)
            for t in self.all_tags
        )

        if self.all_tags and not has_creation_tags:
            flags.append(Flag(
                category="Temporal Indicators",
                name="No Creation Timestamps in Tags",
                severity=0.3,
                description="No creation date tags - organic infra often tracks when resources were created",
                evidence=["No CreatedAt, CreatedOn, or similar tags found"]
            ))
            score += 10

        return CategoryScore("Temporal Indicators", min(score, max_score), max_score, flags)

    def _analyze_structural_realism(self) -> CategoryScore:
        """Check for missing operational infrastructure."""
        flags = []
        score = 0
        max_score = 100

        resource_types = set(self.resources.keys())
        has_vpc = "aws_vpc" in resource_types
        has_instances = "aws_instance" in resource_types or "aws_launch_template" in resource_types

        if not has_vpc and not has_instances:
            return CategoryScore("Structural Realism", 0, max_score, flags)

        # Check for missing bastion/jump hosts
        instance_names = [i["name"].lower() for i in self.resources.get("aws_instance", [])]
        has_bastion = any(
            "bastion" in n or "jump" in n or "ssh" in n
            for n in instance_names
        )
        if has_instances and not has_bastion and len(instance_names) > 2:
            flags.append(Flag(
                category="Structural Realism",
                name="No Bastion/Jump Host",
                severity=0.5,
                description="No bastion or jump host found - common in production environments",
                evidence=["No resources named *bastion*, *jump*, or *ssh*"]
            ))
            score += 20

        # Check for NAT Gateway
        has_nat = "aws_nat_gateway" in resource_types or "aws_eip" in resource_types
        if has_vpc and not has_nat:
            flags.append(Flag(
                category="Structural Realism",
                name="No NAT Gateway",
                severity=0.4,
                description="No NAT gateway for private subnet internet access",
                evidence=["Missing aws_nat_gateway or aws_eip resources"]
            ))
            score += 15

        # Check for VPC Flow Logs
        has_flow_logs = "aws_flow_log" in resource_types
        if has_vpc and not has_flow_logs:
            flags.append(Flag(
                category="Structural Realism",
                name="No VPC Flow Logs",
                severity=0.4,
                description="No flow logs configured - standard for security monitoring",
                evidence=["Missing aws_flow_log resource"]
            ))
            score += 15

        # Check for CloudWatch resources
        has_monitoring = any(
            rt in resource_types
            for rt in ["aws_cloudwatch_log_group", "aws_cloudwatch_metric_alarm", "aws_cloudwatch_dashboard"]
        )
        if has_instances and not has_monitoring:
            flags.append(Flag(
                category="Structural Realism",
                name="No CloudWatch Monitoring",
                severity=0.5,
                description="No CloudWatch logs or alarms - unusual for production",
                evidence=["Missing CloudWatch resources"]
            ))
            score += 20

        # Check for VPC Endpoints
        has_endpoints = "aws_vpc_endpoint" in resource_types
        if has_vpc and not has_endpoints:
            flags.append(Flag(
                category="Structural Realism",
                name="No VPC Endpoints",
                severity=0.3,
                description="No VPC endpoints for AWS services",
                evidence=["Missing aws_vpc_endpoint resources"]
            ))
            score += 10

        # Check for IAM resources
        has_iam = any(
            rt in resource_types
            for rt in ["aws_iam_role", "aws_iam_policy", "aws_iam_instance_profile"]
        )
        if has_instances and not has_iam:
            flags.append(Flag(
                category="Structural Realism",
                name="No IAM Configuration",
                severity=0.6,
                description="No IAM roles or policies - instances need IAM for AWS API access",
                evidence=["Missing IAM resources"]
            ))
            score += 20

        # Check for cross-account references or peering connections
        has_peering = "aws_vpc_peering_connection" in resource_types
        has_cross_account = (
            "aws_ram_resource_share" in resource_types or
            re.search(r'arn:aws:[^:]+:[^:]*:\d{12}:', self.raw_content)  # Cross-account ARN
        )
        has_transit_gateway = "aws_ec2_transit_gateway" in resource_types

        if has_vpc and not has_peering and not has_cross_account and not has_transit_gateway:
            flags.append(Flag(
                category="Structural Realism",
                name="No Cross-Account/Peering",
                severity=0.4,
                description="No VPC peering or cross-account references - enterprise networks are interconnected",
                evidence=["No aws_vpc_peering_connection, transit gateway, or cross-account ARNs found"]
            ))
            score += 15

        # Check for too-clean security groups (no accumulated exceptions)
        sgs = self.resources.get("aws_security_group", [])
        if sgs:
            # Check for signs of organic SG growth: varied port ranges, specific IPs, descriptions
            sg_has_organic_signs = False
            for sg in sgs:
                config = sg["config"]
                if isinstance(config, dict):
                    ingress_rules = config.get("ingress", [])
                    for rule in ingress_rules if isinstance(ingress_rules, list) else []:
                        if isinstance(rule, dict):
                            # Organic signs: specific CIDR (not 0.0.0.0/0), description, unusual ports
                            cidr = rule.get("cidr_blocks", [])
                            desc = rule.get("description", "")
                            from_port = rule.get("from_port", 0)
                            # Check for non-standard ports or specific CIDRs
                            if desc and len(desc) > 10:
                                sg_has_organic_signs = True
                            if isinstance(cidr, list) and cidr and "0.0.0.0/0" not in cidr:
                                sg_has_organic_signs = True
                            if from_port and from_port not in [22, 80, 443, 3306, 5432, 6379, 8080]:
                                sg_has_organic_signs = True

            if not sg_has_organic_signs and len(sgs) > 1:
                flags.append(Flag(
                    category="Structural Realism",
                    name="Too-Clean Security Groups",
                    severity=0.5,
                    description="Security groups lack accumulated exceptions - organic SGs have specific IPs, descriptions, unusual ports",
                    evidence=["No specific CIDR restrictions, no detailed descriptions, only standard ports"]
                ))
                score += 15

        return CategoryScore("Structural Realism", min(score, max_score), max_score, flags)

    def _analyze_configuration_entropy(self) -> CategoryScore:
        """Analyze configuration variety and entropy."""
        flags = []
        score = 0
        max_score = 100

        # Check tag consistency
        if self.all_tags:
            tag_keys_per_resource = [set(t.keys()) if isinstance(t, dict) else set() for t in self.all_tags]
            if tag_keys_per_resource:
                # Check if all resources have identical tag keys
                if len(set(frozenset(tk) for tk in tag_keys_per_resource)) == 1:
                    flags.append(Flag(
                        category="Configuration Entropy",
                        name="Uniform Tag Keys",
                        severity=0.5,
                        description="All resources have identical tag keys - organic tagging is inconsistent",
                        evidence=[f"All resources use tags: {list(tag_keys_per_resource[0])}"]
                    ))
                    score += 20

                # Check for missing common organic tags
                all_tag_keys = set()
                for tk in tag_keys_per_resource:
                    all_tag_keys.update(tk)

                organic_tags = {"Owner", "Team", "CostCenter", "Project", "Environment", "CreatedBy"}
                missing_organic = organic_tags - all_tag_keys
                if len(missing_organic) == len(organic_tags) and self.all_tags:
                    flags.append(Flag(
                        category="Configuration Entropy",
                        name="Missing Operational Tags",
                        severity=0.4,
                        description="Missing common operational tags (Owner, Team, CostCenter)",
                        evidence=[f"None of {organic_tags} found in tags"]
                    ))
                    score += 15
        elif self.resources and sum(len(r) for r in self.resources.values()) > 3:
            flags.append(Flag(
                category="Configuration Entropy",
                name="No Tags Present",
                severity=0.6,
                description="No tags on any resources - organic infra has tagging (even if messy)",
                evidence=["Zero tags found across all resources"]
            ))
            score += 25

        # Check for hardcoded IPs (organic signal)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        hardcoded_ips = re.findall(ip_pattern, self.raw_content)
        # Filter out common non-routable
        real_ips = [ip for ip in hardcoded_ips if not ip.startswith(("0.", "127.", "255."))]

        if not real_ips and len(self.raw_content) > 1000:
            flags.append(Flag(
                category="Configuration Entropy",
                name="No Hardcoded IPs",
                severity=0.3,
                description="No hardcoded IPs found - organic infra often has legacy IP references",
                evidence=["All IPs are parameterized or use CIDR variables"]
            ))
            score += 15

        # Check AMI references
        ami_refs = re.findall(r'ami-[a-f0-9]+', self.raw_content)
        if ami_refs:
            unique_amis = set(ami_refs)
            if len(unique_amis) == 1 and len(ami_refs) > 2:
                flags.append(Flag(
                    category="Configuration Entropy",
                    name="Single AMI Across All Instances",
                    severity=0.4,
                    description="All instances use same AMI - organic environments have varied AMIs",
                    evidence=[f"All instances use {list(unique_amis)[0]}"]
                ))
                score += 15

        # Check region diversity
        region_refs = re.findall(r'[a-z]{2}-[a-z]+-\d', self.raw_content)
        if region_refs:
            unique_regions = set(region_refs)
            if len(unique_regions) == 1:
                flags.append(Flag(
                    category="Configuration Entropy",
                    name="Single Region Deployment",
                    severity=0.3,
                    description="All resources in single region - enterprises typically span regions",
                    evidence=[f"Only region found: {list(unique_regions)[0]}"]
                ))
                score += 10

        return CategoryScore("Configuration Entropy", min(score, max_score), max_score, flags)

    def _analyze_organic_signals(self) -> CategoryScore:
        """Look for organic signals that would lower synthetic score."""
        flags = []
        score = 0
        max_score = 100

        # Start with high score (assuming synthetic) and reduce for organic signals
        score = 80

        # Check for ticket references
        has_tickets = any(
            re.search(pattern, self.raw_content, re.IGNORECASE)
            for pattern in self.TICKET_PATTERNS
        )
        if has_tickets:
            score -= 30
        else:
            flags.append(Flag(
                category="Organic Signals",
                name="No Ticket References",
                severity=0.5,
                description="No JIRA/ticket references found - organic code references tickets",
                evidence=["No patterns like PROJ-1234, #12345, or ticket/issue numbers"]
            ))

        # Check for comments
        comment_patterns = [r'#\s*\w+', r'//\s*\w+', r'/\*']
        comment_count = sum(
            len(re.findall(pattern, self.raw_content))
            for pattern in comment_patterns
        )
        if comment_count > 5:
            score -= 15
        elif comment_count == 0:
            flags.append(Flag(
                category="Organic Signals",
                name="No Comments",
                severity=0.4,
                description="No comments in Terraform files",
                evidence=["Zero comments found"]
            ))

        # Check for TODOs/FIXMEs
        has_todos = re.search(r'(TODO|FIXME|XXX|HACK|WORKAROUND)', self.raw_content, re.IGNORECASE)
        if has_todos:
            score -= 20
        else:
            flags.append(Flag(
                category="Organic Signals",
                name="No TODO/FIXME Comments",
                severity=0.4,
                description="No TODO or FIXME markers - organic code has technical debt markers",
                evidence=["No TODO, FIXME, XXX, HACK, or WORKAROUND found"]
            ))

        # Check for commented-out code
        commented_code_patterns = [
            r'#\s*resource\s',
            r'#\s*aws_',
            r'#\s*\w+\s*=',
        ]
        has_commented_code = any(
            re.search(pattern, self.raw_content)
            for pattern in commented_code_patterns
        )
        if has_commented_code:
            score -= 15
        else:
            flags.append(Flag(
                category="Organic Signals",
                name="No Commented-Out Code",
                severity=0.3,
                description="No commented-out code - organic configs have disabled sections",
                evidence=["No commented resource blocks or configurations"]
            ))

        # Check for description fields (organic signal)
        descriptions = re.findall(r'description\s*=\s*"[^"]{20,}"', self.raw_content)
        if len(descriptions) > 2:
            score -= 10

        # Check for troubleshooting/debug configurations (organic signal)
        debug_patterns = [
            r'debug',
            r'troubleshoot',
            r'temporary',
            r'temp[-_]rule',
            r'allow[-_]all',  # Temporary allow-all rules
            r'test[-_]',
            r'testing',
            r'remove[-_]?later',
            r'revert',
            r'hotfix',
        ]
        has_debug_config = any(
            re.search(pattern, self.raw_content, re.IGNORECASE)
            for pattern in debug_patterns
        )
        if has_debug_config:
            score -= 20
        else:
            if len(self.resources) > 5:
                flags.append(Flag(
                    category="Organic Signals",
                    name="No Debug/Troubleshooting Artifacts",
                    severity=0.4,
                    description="No temporary rules or debug configs - organic infra has troubleshooting remnants",
                    evidence=["No 'debug', 'temporary', 'test-', 'hotfix' patterns found"]
                ))

        # Check for environment-specific overrides (organic signal)
        env_patterns = [
            r'override',
            r'except',
            r'unless',
            r'special[-_]?case',
            r'workaround',
            r'one[-_]?off',
        ]
        has_overrides = any(
            re.search(pattern, self.raw_content, re.IGNORECASE)
            for pattern in env_patterns
        )
        if has_overrides:
            score -= 15

        return CategoryScore("Organic Signals", max(score, 0), max_score, flags)

    def _analyze_code_artifacts(self) -> CategoryScore:
        """Analyze code-level artifacts and patterns."""
        flags = []
        score = 0
        max_score = 100

        # Check for lifecycle blocks (organic signal - indicates iteration)
        has_lifecycle = "lifecycle" in self.raw_content
        if not has_lifecycle and len(self.resources) > 5:
            flags.append(Flag(
                category="Code Artifacts",
                name="No Lifecycle Blocks",
                severity=0.3,
                description="No lifecycle configurations - organic infra often has create_before_destroy, etc.",
                evidence=["No lifecycle {} blocks found"]
            ))
            score += 15

        # Check for count/for_each (could go either way)
        has_iteration = "count" in self.raw_content or "for_each" in self.raw_content
        if has_iteration:
            # Check if it's simple sequential iteration
            simple_count = re.findall(r'count\s*=\s*\d+', self.raw_content)
            if simple_count:
                flags.append(Flag(
                    category="Code Artifacts",
                    name="Simple Count Iteration",
                    severity=0.4,
                    description="Using simple count for resource creation - common in synthetic setups",
                    evidence=simple_count[:3]
                ))
                score += 20

        # Check for depends_on (organic signal - indicates discovered dependencies)
        has_depends = "depends_on" in self.raw_content
        if not has_depends and len(self.resources) > 5:
            flags.append(Flag(
                category="Code Artifacts",
                name="No Explicit Dependencies",
                severity=0.3,
                description="No depends_on blocks - organic configs often have explicit dependency management",
                evidence=["No depends_on found"]
            ))
            score += 15

        # Check for data sources (organic signal - reading existing resources)
        data_sources = re.findall(r'data\s+"aws_', self.raw_content)
        if not data_sources and len(self.resources) > 3:
            flags.append(Flag(
                category="Code Artifacts",
                name="No Data Sources",
                severity=0.4,
                description="No data sources - organic configs reference existing resources",
                evidence=["No data blocks for existing AWS resources"]
            ))
            score += 20

        # Check for modules (organic signal - code reuse)
        module_refs = re.findall(r'module\s+"', self.raw_content)
        if not module_refs and len(self.resources) > 10:
            flags.append(Flag(
                category="Code Artifacts",
                name="No Module Usage",
                severity=0.3,
                description="No modules used - larger organic configs typically use modules",
                evidence=["No module blocks found"]
            ))
            score += 15

        # Check for provider configuration complexity
        provider_configs = re.findall(r'provider\s+"aws"', self.raw_content)
        if len(provider_configs) <= 1:
            # Check for assume_role (organic signal)
            if "assume_role" not in self.raw_content:
                flags.append(Flag(
                    category="Code Artifacts",
                    name="Simple Provider Config",
                    severity=0.3,
                    description="No cross-account or assume_role configurations",
                    evidence=["Single simple provider block"]
                ))
                score += 10

        return CategoryScore("Code Artifacts", min(score, max_score), max_score, flags)

    def _extract_name_formats(self) -> dict[str, int]:
        """Extract naming format patterns from resource names."""
        formats = {}
        for name in self.all_names:
            # Normalize to pattern
            pattern = re.sub(r'\d+', 'N', name)
            pattern = re.sub(r'[a-f0-9]{8,}', 'HASH', pattern)
            formats[pattern] = formats.get(pattern, 0) + 1
        return formats

    def _check_naming_inconsistencies(self) -> bool:
        """Check if there are any naming inconsistencies (organic signal)."""
        if len(self.all_names) < 3:
            return False

        # Check for mixed separators
        has_dash = any('-' in n for n in self.all_names)
        has_underscore = any('_' in n for n in self.all_names)
        if has_dash and has_underscore:
            return True

        # Check for mixed casing patterns
        has_lower = any(n.islower() for n in self.all_names)
        has_mixed = any(not n.islower() and not n.isupper() for n in self.all_names)
        if has_lower and has_mixed:
            return True

        return False

    def _get_cidr_size(self, cidr: str) -> int:
        """Extract the prefix size from a CIDR block."""
        if '/' in cidr:
            try:
                return int(cidr.split('/')[1])
            except (ValueError, IndexError):
                pass
        return 0

    def _cidrs_are_sequential(self, cidrs: list[str]) -> bool:
        """Check if CIDR blocks are sequentially allocated."""
        if len(cidrs) < 2:
            return False

        try:
            # Extract the third octet and check for sequence
            octets = []
            for cidr in cidrs:
                parts = cidr.split('.')
                if len(parts) >= 3:
                    octets.append(int(parts[2]))

            if len(octets) >= 2:
                octets.sort()
                # Check if sequential
                for i in range(1, len(octets)):
                    if octets[i] - octets[i-1] != 1:
                        return False
                return True
        except (ValueError, IndexError):
            pass

        return False

    def _generate_summary(self, result: AnalysisResult) -> str:
        """Generate a human-readable summary."""
        total_flags = sum(len(cat.flags) for cat in result.categories)

        if result.synthetic_score >= 75:
            verdict = "This infrastructure shows strong indicators of being synthetically generated or a honeypot."
        elif result.synthetic_score >= 50:
            verdict = "This infrastructure has significant synthetic characteristics but some organic elements."
        elif result.synthetic_score >= 30:
            verdict = "Mixed signals - some synthetic patterns but also organic characteristics present."
        else:
            verdict = "This infrastructure appears to be organically grown with typical operational artifacts."

        top_categories = sorted(result.categories, key=lambda c: c.normalized_score, reverse=True)[:3]
        top_concerns = ", ".join(c.name for c in top_categories if c.normalized_score > 30)

        summary = f"{verdict} "
        if top_concerns:
            summary += f"Primary concerns: {top_concerns}. "
        summary += f"Analysis based on {total_flags} triggered flags with {result.confidence} confidence."

        return summary
