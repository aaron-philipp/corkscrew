"""Core analysis engine for detecting synthetic/honeypot Terraform configurations."""
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

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
    provider: str  # aws, gcp, multi, unknown
    categories: list[CategoryScore] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "synthetic_score": round(self.synthetic_score, 1),
            "confidence": self.confidence,
            "provider": self.provider,
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

    # Resource type mappings: category -> (AWS types, GCP types)
    RESOURCE_MAPPINGS = {
        "vpc": (["aws_vpc"], ["google_compute_network"]),
        "subnet": (["aws_subnet"], ["google_compute_subnetwork"]),
        "instance": (
            ["aws_instance", "aws_launch_template"],
            ["google_compute_instance", "google_compute_instance_template"]
        ),
        "security_group": (
            ["aws_security_group"],
            ["google_compute_firewall"]
        ),
        "nat": (
            ["aws_nat_gateway", "aws_eip"],
            ["google_compute_router_nat", "google_compute_router"]
        ),
        "flow_log": (
            ["aws_flow_log"],
            ["google_compute_subnetwork"]  # GCP uses log_config in subnetwork
        ),
        "monitoring": (
            ["aws_cloudwatch_log_group", "aws_cloudwatch_metric_alarm", "aws_cloudwatch_dashboard"],
            ["google_logging_metric", "google_monitoring_alert_policy", "google_monitoring_dashboard",
             "google_logging_project_sink"]
        ),
        "vpc_endpoint": (
            ["aws_vpc_endpoint"],
            ["google_compute_global_address", "google_service_networking_connection"]
        ),
        "iam": (
            ["aws_iam_role", "aws_iam_policy", "aws_iam_instance_profile"],
            ["google_service_account", "google_project_iam_member", "google_project_iam_binding",
             "google_service_account_iam_member"]
        ),
        "peering": (
            ["aws_vpc_peering_connection", "aws_ec2_transit_gateway"],
            ["google_compute_network_peering", "google_compute_interconnect_attachment"]
        ),
        "load_balancer": (
            ["aws_lb", "aws_alb", "aws_elb"],
            ["google_compute_forwarding_rule", "google_compute_target_pool",
             "google_compute_backend_service", "google_compute_url_map"]
        ),
    }

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
        r'^vm[-_]\d+$',
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
        self.detected_provider: str = "unknown"

    def parse_directory(self, path: Path) -> None:
        """Parse all .tf files in a directory."""
        tf_files = list(path.glob("**/*.tf"))
        if not tf_files:
            raise ValueError(f"No .tf files found in {path}")

        for tf_file in tf_files:
            self._parse_file(tf_file)

        self._detect_provider()

    def parse_file(self, path: Path) -> None:
        """Parse a single .tf file."""
        self._parse_file(path)
        self._detect_provider()

    def _parse_file(self, path: Path) -> None:
        """Internal method to parse a Terraform file."""
        content = path.read_text(encoding='utf-8')
        self.raw_content += content + "\n"
        self.files_parsed += 1

        try:
            parsed = hcl2.loads(content)
        except Exception as e:
            raise ValueError(f"Failed to parse {path}: {e}") from e

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
                    # Extract tags (AWS uses 'tags', GCP uses 'labels')
                    if isinstance(config, dict):
                        if "tags" in config:
                            self.all_tags.append(config["tags"])
                        if "labels" in config:
                            self.all_tags.append(config["labels"])

        # Extract variables
        for var in parsed.get("variable", []):
            self.variables.update(var)

        # Extract locals
        for local in parsed.get("locals", []):
            self.locals.update(local)

    def _detect_provider(self) -> None:
        """Detect which cloud provider(s) are being used."""
        resource_types = set(self.resources.keys())

        has_aws = any(rt.startswith("aws_") for rt in resource_types)
        has_gcp = any(rt.startswith("google_") for rt in resource_types)

        if has_aws and has_gcp:
            self.detected_provider = "multi"
        elif has_aws:
            self.detected_provider = "aws"
        elif has_gcp:
            self.detected_provider = "gcp"
        else:
            self.detected_provider = "unknown"

    def _get_resources_by_category(self, category: str) -> list[dict]:
        """Get all resources matching a category across providers."""
        aws_types, gcp_types = self.RESOURCE_MAPPINGS.get(category, ([], []))
        resources = []
        for rt in aws_types + gcp_types:
            resources.extend(self.resources.get(rt, []))
        return resources

    def _has_resource_category(self, category: str) -> bool:
        """Check if any resources exist for a category."""
        return len(self._get_resources_by_category(category)) > 0

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
            provider=self.detected_provider,
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

        # Check subnet configurations (AWS and GCP)
        subnets = self._get_resources_by_category("subnet")
        if len(subnets) >= 2:
            # AWS uses cidr_block, GCP uses ip_cidr_range
            cidr_blocks = []
            for s in subnets:
                if isinstance(s["config"], dict):
                    cidr = s["config"].get("cidr_block") or s["config"].get("ip_cidr_range", "")
                    if cidr:
                        cidr_blocks.append(cidr)

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

        # Check security group/firewall symmetry
        sgs = self._get_resources_by_category("security_group")
        if len(sgs) >= 2:
            rule_counts = []
            for sg in sgs:
                config = sg["config"]
                if isinstance(config, dict):
                    # AWS: ingress/egress, GCP: allow/deny
                    ingress = len(config.get("ingress", []) or config.get("allow", []))
                    egress = len(config.get("egress", []) or config.get("deny", []))
                    rule_counts.append((ingress, egress))

            if rule_counts and len(set(rule_counts)) == 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Identical Security Group Structure",
                    severity=0.6,
                    description="All security groups/firewalls have identical rule counts",
                    evidence=[f"All have {rule_counts[0][0]} ingress/allow, {rule_counts[0][1]} egress/deny rules"]
                ))
                score += 25

        # Check instance type distribution
        instances = self._get_resources_by_category("instance")
        if len(instances) >= 3:
            instance_types = []
            for i in instances:
                if isinstance(i["config"], dict):
                    # AWS: instance_type, GCP: machine_type
                    itype = i["config"].get("instance_type") or i["config"].get("machine_type", "")
                    if itype:
                        instance_types.append(itype)

            if instance_types and len(set(instance_types)) == 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Uniform Instance Types",
                    severity=0.5,
                    description="All instances use identical instance/machine type",
                    evidence=[f"All instances are {instance_types[0]}"]
                ))
                score += 20

        # Check AZ/Zone distribution
        az_resources = []
        for _resource_type, resources in self.resources.items():
            for r in resources:
                if isinstance(r["config"], dict):
                    # AWS: availability_zone, GCP: zone
                    az = r["config"].get("availability_zone") or r["config"].get("zone", "")
                    if az:
                        az_resources.append(az)

        if az_resources:
            az_counts = Counter(az_resources)
            if len(set(az_counts.values())) == 1 and len(az_counts) > 1:
                flags.append(Flag(
                    category="Resource Symmetry",
                    name="Perfect AZ/Zone Balance",
                    severity=0.4,
                    description="Resources perfectly balanced across AZs/zones - organic deployment drifts",
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

        # Check for creation timestamp in tags/labels
        creation_tags = ['CreatedAt', 'CreatedOn', 'CreateDate', 'created_at', 'created_on', 'creation_timestamp']
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

        has_vpc = self._has_resource_category("vpc")
        has_instances = self._has_resource_category("instance")

        if not has_vpc and not has_instances:
            return CategoryScore("Structural Realism", 0, max_score, flags)

        # Check for missing bastion/jump hosts
        instances = self._get_resources_by_category("instance")
        instance_names = [i["name"].lower() for i in instances]
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

        # Check for NAT Gateway/Cloud NAT
        has_nat = self._has_resource_category("nat")
        if has_vpc and not has_nat:
            flags.append(Flag(
                category="Structural Realism",
                name="No NAT Gateway/Cloud NAT",
                severity=0.4,
                description="No NAT for private subnet internet access",
                evidence=["Missing NAT gateway resources"]
            ))
            score += 15

        # Check for VPC Flow Logs / GCP VPC Flow Logs
        has_flow_logs = self._has_resource_category("flow_log")
        # For GCP, also check if subnets have log_config
        if self.detected_provider == "gcp":
            for subnet in self._get_resources_by_category("subnet"):
                if isinstance(subnet["config"], dict) and "log_config" in subnet["config"]:
                    has_flow_logs = True
                    break

        if has_vpc and not has_flow_logs:
            flags.append(Flag(
                category="Structural Realism",
                name="No VPC Flow Logs",
                severity=0.4,
                description="No flow logs configured - standard for security monitoring",
                evidence=["Missing flow log configuration"]
            ))
            score += 15

        # Check for CloudWatch / Stackdriver monitoring
        has_monitoring = self._has_resource_category("monitoring")
        if has_instances and not has_monitoring:
            flags.append(Flag(
                category="Structural Realism",
                name="No Cloud Monitoring",
                severity=0.5,
                description="No monitoring/logging resources - unusual for production",
                evidence=["Missing monitoring resources"]
            ))
            score += 20

        # Check for VPC Endpoints / Private Service Connect
        has_endpoints = self._has_resource_category("vpc_endpoint")
        if has_vpc and not has_endpoints:
            flags.append(Flag(
                category="Structural Realism",
                name="No Private Service Endpoints",
                severity=0.3,
                description="No VPC endpoints or private service connections",
                evidence=["Missing private endpoint resources"]
            ))
            score += 10

        # Check for IAM resources
        has_iam = self._has_resource_category("iam")
        if has_instances and not has_iam:
            flags.append(Flag(
                category="Structural Realism",
                name="No IAM Configuration",
                severity=0.6,
                description="No IAM roles/service accounts - instances need identity for API access",
                evidence=["Missing IAM/service account resources"]
            ))
            score += 20

        # Check for cross-account/cross-project references or peering connections
        has_peering = self._has_resource_category("peering")
        # Check for cross-account ARNs (AWS) or cross-project references (GCP)
        has_cross_account = (
            re.search(r'arn:aws:[^:]+:[^:]*:\d{12}:', self.raw_content) or  # AWS cross-account ARN
            re.search(r'projects/[a-z][a-z0-9-]+/', self.raw_content)  # GCP cross-project
        )

        if has_vpc and not has_peering and not has_cross_account:
            flags.append(Flag(
                category="Structural Realism",
                name="No Cross-Account/Cross-Project",
                severity=0.4,
                description="No VPC peering or cross-account/project references - enterprise networks are interconnected",
                evidence=["No peering connections or cross-account/project references found"]
            ))
            score += 15

        # Check for too-clean security groups/firewalls
        sgs = self._get_resources_by_category("security_group")
        if sgs:
            sg_has_organic_signs = False
            for sg in sgs:
                config = sg["config"]
                if isinstance(config, dict):
                    # Check AWS ingress rules
                    ingress_rules = config.get("ingress", [])
                    # Check GCP allow rules
                    allow_rules = config.get("allow", [])

                    for rule in (ingress_rules if isinstance(ingress_rules, list) else []):
                        if isinstance(rule, dict):
                            cidr = rule.get("cidr_blocks", [])
                            desc = rule.get("description", "")
                            from_port = rule.get("from_port", 0)
                            if desc and len(desc) > 10:
                                sg_has_organic_signs = True
                            if isinstance(cidr, list) and cidr and "0.0.0.0/0" not in cidr:
                                sg_has_organic_signs = True
                            if from_port and from_port not in [22, 80, 443, 3306, 5432, 6379, 8080]:
                                sg_has_organic_signs = True

                    for rule in (allow_rules if isinstance(allow_rules, list) else []):
                        if isinstance(rule, dict):
                            ports = rule.get("ports", [])
                            if ports and any(p not in ["22", "80", "443", "3306", "5432"] for p in ports):
                                sg_has_organic_signs = True

            if not sg_has_organic_signs and len(sgs) > 1:
                flags.append(Flag(
                    category="Structural Realism",
                    name="Too-Clean Security Rules",
                    severity=0.5,
                    description="Security groups/firewalls lack accumulated exceptions",
                    evidence=["No specific CIDR restrictions, no detailed descriptions, only standard ports"]
                ))
                score += 15

        return CategoryScore("Structural Realism", min(score, max_score), max_score, flags)

    def _analyze_configuration_entropy(self) -> CategoryScore:
        """Analyze configuration variety and entropy."""
        flags = []
        score = 0
        max_score = 100

        # Check tag/label consistency
        if self.all_tags:
            tag_keys_per_resource = [set(t.keys()) if isinstance(t, dict) else set() for t in self.all_tags]
            if tag_keys_per_resource:
                if len({frozenset(tk) for tk in tag_keys_per_resource}) == 1:
                    flags.append(Flag(
                        category="Configuration Entropy",
                        name="Uniform Tag/Label Keys",
                        severity=0.5,
                        description="All resources have identical tag/label keys - organic tagging is inconsistent",
                        evidence=[f"All resources use: {list(tag_keys_per_resource[0])}"]
                    ))
                    score += 20

                all_tag_keys = set()
                for tk in tag_keys_per_resource:
                    all_tag_keys.update(tk)

                # Common organic tags for both AWS and GCP
                organic_tags = {"Owner", "Team", "CostCenter", "Project", "Environment", "CreatedBy",
                               "owner", "team", "cost-center", "project", "environment", "created-by"}
                has_any_organic = bool(organic_tags & all_tag_keys)
                if not has_any_organic and self.all_tags:
                    flags.append(Flag(
                        category="Configuration Entropy",
                        name="Missing Operational Tags",
                        severity=0.4,
                        description="Missing common operational tags (Owner, Team, CostCenter)",
                        evidence=["No common operational tags found"]
                    ))
                    score += 15
        elif self.resources and sum(len(r) for r in self.resources.values()) > 3:
            flags.append(Flag(
                category="Configuration Entropy",
                name="No Tags/Labels Present",
                severity=0.6,
                description="No tags/labels on any resources - organic infra has tagging (even if messy)",
                evidence=["Zero tags/labels found across all resources"]
            ))
            score += 25

        # Check for hardcoded IPs (organic signal)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        hardcoded_ips = re.findall(ip_pattern, self.raw_content)
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

        # Check image references (AMI for AWS, image for GCP)
        ami_refs = re.findall(r'ami-[a-f0-9]+', self.raw_content)
        gcp_image_refs = re.findall(r'projects/[^/]+/global/images/[^\s"]+', self.raw_content)
        image_refs = ami_refs + gcp_image_refs

        if image_refs:
            unique_images = set(image_refs)
            if len(unique_images) == 1 and len(image_refs) > 2:
                flags.append(Flag(
                    category="Configuration Entropy",
                    name="Single Image Across All Instances",
                    severity=0.4,
                    description="All instances use same image - organic environments have varied images",
                    evidence=[f"All instances use {list(unique_images)[0][:50]}..."]
                ))
                score += 15

        # Check region/location diversity
        aws_regions = re.findall(r'[a-z]{2}-[a-z]+-\d', self.raw_content)
        gcp_regions = re.findall(r'[a-z]+-[a-z]+\d', self.raw_content)
        regions = set(aws_regions + gcp_regions)

        if regions and len(regions) == 1:
            flags.append(Flag(
                category="Configuration Entropy",
                name="Single Region Deployment",
                severity=0.3,
                description="All resources in single region - enterprises typically span regions",
                evidence=[f"Only region found: {list(regions)[0]}"]
            ))
            score += 10

        return CategoryScore("Configuration Entropy", min(score, max_score), max_score, flags)

    def _analyze_organic_signals(self) -> CategoryScore:
        """Look for organic signals that would lower synthetic score."""
        flags = []
        score = 80  # Start high, reduce for organic signals
        max_score = 100

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
            r'#\s*(aws_|google_)',
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

        # Check for description fields
        descriptions = re.findall(r'description\s*=\s*"[^"]{20,}"', self.raw_content)
        if len(descriptions) > 2:
            score -= 10

        # Check for troubleshooting/debug configurations
        debug_patterns = [
            r'debug', r'troubleshoot', r'temporary', r'temp[-_]rule',
            r'allow[-_]all', r'test[-_]', r'testing', r'remove[-_]?later',
            r'revert', r'hotfix',
        ]
        has_debug_config = any(
            re.search(pattern, self.raw_content, re.IGNORECASE)
            for pattern in debug_patterns
        )
        if has_debug_config:
            score -= 20
        elif len(self.resources) > 5:
            flags.append(Flag(
                category="Organic Signals",
                name="No Debug/Troubleshooting Artifacts",
                severity=0.4,
                description="No temporary rules or debug configs - organic infra has troubleshooting remnants",
                evidence=["No 'debug', 'temporary', 'test-', 'hotfix' patterns found"]
            ))

        # Check for environment-specific overrides
        env_patterns = [r'override', r'except', r'unless', r'special[-_]?case', r'workaround', r'one[-_]?off']
        has_overrides = any(re.search(pattern, self.raw_content, re.IGNORECASE) for pattern in env_patterns)
        if has_overrides:
            score -= 15

        return CategoryScore("Organic Signals", max(score, 0), max_score, flags)

    def _analyze_code_artifacts(self) -> CategoryScore:
        """Analyze code-level artifacts and patterns."""
        flags = []
        score = 0
        max_score = 100

        # Check for lifecycle blocks
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

        # Check for count/for_each
        has_iteration = "count" in self.raw_content or "for_each" in self.raw_content
        if has_iteration:
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

        # Check for depends_on
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

        # Check for data sources
        data_sources = re.findall(r'data\s+"(aws_|google_)', self.raw_content)
        if not data_sources and len(self.resources) > 3:
            flags.append(Flag(
                category="Code Artifacts",
                name="No Data Sources",
                severity=0.4,
                description="No data sources - organic configs reference existing resources",
                evidence=["No data blocks for existing resources"]
            ))
            score += 20

        # Check for modules
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
        aws_providers = re.findall(r'provider\s+"aws"', self.raw_content)
        gcp_providers = re.findall(r'provider\s+"google"', self.raw_content)
        total_providers = len(aws_providers) + len(gcp_providers)

        if total_providers <= 1:
            if "assume_role" not in self.raw_content and "impersonate_service_account" not in self.raw_content:
                flags.append(Flag(
                    category="Code Artifacts",
                    name="Simple Provider Config",
                    severity=0.3,
                    description="No cross-account/project or assume_role/impersonation configurations",
                    evidence=["Single simple provider block"]
                ))
                score += 10

        return CategoryScore("Code Artifacts", min(score, max_score), max_score, flags)

    def _extract_name_formats(self) -> dict[str, int]:
        """Extract naming format patterns from resource names."""
        formats = {}
        for name in self.all_names:
            pattern = re.sub(r'\d+', 'N', name)
            pattern = re.sub(r'[a-f0-9]{8,}', 'HASH', pattern)
            formats[pattern] = formats.get(pattern, 0) + 1
        return formats

    def _check_naming_inconsistencies(self) -> bool:
        """Check if there are any naming inconsistencies (organic signal)."""
        if len(self.all_names) < 3:
            return False

        has_dash = any('-' in n for n in self.all_names)
        has_underscore = any('_' in n for n in self.all_names)
        if has_dash and has_underscore:
            return True

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
            octets = []
            for cidr in cidrs:
                parts = cidr.split('.')
                if len(parts) >= 3:
                    octets.append(int(parts[2]))

            if len(octets) >= 2:
                octets.sort()
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

        provider_str = {
            "aws": "AWS",
            "gcp": "GCP",
            "multi": "multi-cloud (AWS + GCP)",
            "unknown": "unknown provider"
        }.get(result.provider, result.provider)

        if result.synthetic_score >= 75:
            verdict = f"This {provider_str} infrastructure shows strong indicators of being synthetically generated or a honeypot."
        elif result.synthetic_score >= 50:
            verdict = f"This {provider_str} infrastructure has significant synthetic characteristics but some organic elements."
        elif result.synthetic_score >= 30:
            verdict = f"Mixed signals in this {provider_str} config - some synthetic patterns but also organic characteristics present."
        else:
            verdict = f"This {provider_str} infrastructure appears to be organically grown with typical operational artifacts."

        top_categories = sorted(result.categories, key=lambda c: c.normalized_score, reverse=True)[:3]
        top_concerns = ", ".join(c.name for c in top_categories if c.normalized_score > 30)

        summary = f"{verdict} "
        if top_concerns:
            summary += f"Primary concerns: {top_concerns}. "
        summary += f"Analysis based on {total_flags} triggered flags with {result.confidence} confidence."

        return summary
