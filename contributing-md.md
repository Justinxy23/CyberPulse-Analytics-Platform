# Contributing to CyberPulse Analytics Platform

First off, thank you for considering contributing to CyberPulse! It's people like you that make CyberPulse such a great tool for the security community.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Process](#development-process)
- [Style Guidelines](#style-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@cyberpulse.io.

### Our Standards

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Node.js 16 or higher
- Docker and Docker Compose
- PostgreSQL 13+
- Redis 6+
- Git

### Development Environment Setup

1. **Fork the repository**
   ```bash
   # Click "Fork" button on GitHub
   git clone https://github.com/YOUR_USERNAME/cyberpulse-analytics.git
   cd cyberpulse-analytics
   ```

2. **Set up Python environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Set up pre-commit hooks**
   ```bash
   pre-commit install
   ```

4. **Copy environment configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your local settings
   ```

5. **Start development services**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

6. **Run database migrations**
   ```bash
   alembic upgrade head
   ```

7. **Run tests to verify setup**
   ```bash
   pytest
   ```

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, please include:

- **Clear, descriptive title**
- **Steps to reproduce**
  1. Go to '...'
  2. Click on '....'
  3. Scroll down to '....'
  4. See error
- **Expected behavior**
- **Actual behavior**
- **Screenshots** (if applicable)
- **Environment details**
  - OS: [e.g., Ubuntu 20.04]
  - Python version
  - Browser (for UI issues)
  - Version of CyberPulse

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Clear, descriptive title**
- **Detailed description** of the proposed functionality
- **Use case** - why is this enhancement useful?
- **Possible implementation** (optional)
- **Mock-ups or examples** (if applicable)

### Your First Code Contribution

Unsure where to begin? Look for these tags in our issues:

- `good-first-issue` - Simple issues ideal for beginners
- `help-wanted` - Issues where we need community help
- `documentation` - Documentation improvements
- `enhancement` - New features or improvements

### Pull Requests

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

2. **Make your changes**
   - Write clean, documented code
   - Add/update tests
   - Update documentation

3. **Test your changes**
   ```bash
   # Run unit tests
   pytest tests/unit/
   
   # Run integration tests
   pytest tests/integration/
   
   # Run linting
   flake8 src/
   black --check src/
   mypy src/
   ```

4. **Commit your changes** (see [Commit Guidelines](#commit-guidelines))

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**

## Development Process

### Project Structure
```
cyberpulse-analytics/
├── src/
│   ├── api/           # FastAPI application
│   ├── core/          # Core business logic
│   ├── models/        # Database models
│   ├── services/      # External service integrations
│   ├── tasks/         # Celery tasks
│   └── utils/         # Utility functions
├── tests/
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   └── fixtures/      # Test fixtures
├── database/
│   ├── migrations/    # Alembic migrations
│   └── schema/        # SQL schemas
├── scripts/           # Utility scripts
├── docs/              # Documentation
└── k8s/               # Kubernetes manifests
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_threat_detector.py

# Run tests matching pattern
pytest -k "test_security"
```

### Database Migrations

```bash
# Create a new migration
alembic revision -m "Add new column to security_events"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1
```

## Style Guidelines

### Python Style Guide

We follow PEP 8 with these additions:
- Line length: 120 characters
- Use type hints for function parameters and returns
- Docstrings for all public functions (Google style)

```python
def calculate_risk_score(
    event: SecurityEvent,
    threat_intel: Dict[str, Any],
    ml_model: Optional[Model] = None
) -> float:
    """Calculate risk score for a security event.
    
    Args:
        event: The security event to analyze
        threat_intel: Threat intelligence data
        ml_model: Optional ML model for scoring
        
    Returns:
        Risk score between 0.0 and 1.0
        
    Raises:
        ValueError: If event data is invalid
    """
    # Implementation
```

### JavaScript/TypeScript Style Guide

- Use ESLint configuration
- Prefer functional components in React
- Use TypeScript for new code

### SQL Style Guide

- Use UPPERCASE for SQL keywords
- Use snake_case for table and column names
- Add comments for complex queries

```sql
-- Get recent high-severity events
SELECT 
    e.event_id,
    e.source_ip,
    e.severity,
    COUNT(a.alert_id) AS alert_count
FROM 
    security_events e
    LEFT JOIN security_alerts a ON e.event_id = a.event_id
WHERE 
    e.severity IN ('HIGH', 'CRITICAL')
    AND e.timestamp > NOW() - INTERVAL '24 hours'
GROUP BY 
    e.event_id, e.source_ip, e.severity
ORDER BY 
    alert_count DESC;
```

## Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Other changes

### Examples
```bash
feat(api): add vulnerability scan endpoint

- Implement POST /api/v1/security/scan
- Add input validation for scan requests
- Queue scans using Celery

Closes #123
```

```bash
fix(auth): prevent timing attacks on login

Use constant-time comparison for password verification
to prevent timing-based attacks.

Security: CVE-2024-xxxxx
```

## Pull Request Process

1. **Before submitting:**
   - Update documentation
   - Add tests for new functionality
   - Ensure all tests pass
   - Update CHANGELOG.md
   - Rebase on latest main branch

2. **PR Description Template:**
   ```markdown
   ## Description
   Brief description of changes
   
   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update
   
   ## Testing
   - [ ] Unit tests pass
   - [ ] Integration tests pass
   - [ ] Manual testing completed
   
   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Comments added for complex code
   - [ ] Documentation updated
   - [ ] No new warnings
   ```

3. **Review Process:**
   - At least one maintainer approval required
   - All CI checks must pass
   - No merge conflicts
   - Updated with latest main branch

## Security Vulnerabilities

**Do not** open issues for security vulnerabilities. Instead:

1. Email security@cyberpulse.io
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We'll respond within 48 hours and work with you to resolve the issue.

## Community

### Communication Channels

- **GitHub Discussions**: General discussions and questions
- **Slack**: [Join our Slack](https://cyberpulse.slack.com)
- **Twitter**: [@CyberPulseIO](https://twitter.com/CyberPulseIO)
- **Blog**: [blog.cyberpulse.io](https://blog.cyberpulse.io)

### Recognition

Contributors who make significant contributions will be:
- Added to our CONTRIBUTORS.md file
- Mentioned in release notes
- Invited to join our Contributors team

## Questions?

Feel free to:
- Open a GitHub Discussion
- Ask in our Slack channel
- Email contributors@cyberpulse.io

Thank you for contributing to CyberPulse! 🚀🔒

---

*Last updated: January 2024*