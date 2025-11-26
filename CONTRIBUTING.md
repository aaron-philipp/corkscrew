# Contributing to CorkScrew

Thank you for your interest in contributing to CorkScrew! This document provides guidelines and information for contributors.

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - CorkScrew version (`pip show corkscrew`)
   - Python version
   - Operating system
   - Minimal Terraform example that reproduces the issue
   - Expected vs actual behavior

### Suggesting Features

1. Check existing issues and discussions
2. Use the feature request template
3. Describe the use case and why it would be valuable
4. If proposing a new heuristic, explain the detection logic

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-heuristic`)
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/corkscrew.git
cd corkscrew

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## Code Style

- Follow PEP 8
- Use type hints
- Keep functions focused and well-documented
- Use descriptive variable names

## Adding New Heuristics

When adding a new detection heuristic:

1. **Identify the category**: Does it fit in an existing category or need a new one?

2. **Implement the check** in `analyzer.py`:
   ```python
   def _analyze_category(self) -> CategoryScore:
       flags = []
       score = 0

       # Your detection logic
       if condition_detected:
           flags.append(Flag(
               category="Category Name",
               name="Heuristic Name",
               severity=0.5,  # 0-1, contribution weight
               description="What this indicates",
               evidence=["specific", "evidence", "items"]
           ))
           score += 20  # Contribution to category score

       return CategoryScore("Category Name", score, max_score, flags)
   ```

3. **Add tests** with sample Terraform that triggers (and doesn't trigger) the heuristic

4. **Update documentation** in README.md

## Heuristic Guidelines

Good heuristics should:

- Have a clear rationale for why they indicate synthetic infrastructure
- Minimize false positives on legitimate production configurations
- Provide actionable evidence in the output
- Work across different Terraform coding styles

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=corkscrew

# Run specific test
pytest tests/test_analyzer.py::test_naming_patterns
```

## Sample Files

The `samples/` directory contains example Terraform configurations:

- `samples/synthetic/` - Example synthetic/honeypot infrastructure
- `samples/organic/` - Example organic production infrastructure

When adding heuristics, consider adding sample files that demonstrate them.

## Questions?

Open a discussion or issue if you have questions about contributing.
