# Contributing to KMIM

Thank you for your interest in contributing to the Kernel Module Integrity Monitor (KMIM)! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Bugs

1. **Check existing issues** first to avoid duplicates
2. **Use the bug report template** when creating a new issue
3. **Provide detailed information**:
   - Operating system and version
   - Python version
   - Kernel version
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages and logs

### Suggesting Features

1. **Check existing feature requests** to avoid duplicates
2. **Use the feature request template**
3. **Provide clear rationale** for the feature
4. **Include use cases** and examples

### Code Contributions

#### Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature/fix
4. Set up the development environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Set up eBPF development
cd ebpf && make all
```

#### Development Guidelines

##### Code Style
- **Python**: Follow PEP 8, use `black` for formatting
- **C/eBPF**: Follow Linux kernel coding style
- **Documentation**: Use clear, concise language

##### Testing
- Write tests for new features
- Ensure all tests pass before submitting
- Maintain or improve code coverage

```bash
# Run Python tests
python -m pytest tests/

# Run eBPF tests
cd ebpf && make test

# Check code style
black --check cli/ tests/
flake8 cli/ tests/
```

##### Commit Messages
Use conventional commits format:
```
type(scope): description

[optional body]

[optional footer(s)]
```

Examples:
- `feat(cli): add syscall monitoring command`
- `fix(ebpf): resolve compilation warnings`
- `docs(readme): update installation instructions`

#### Pull Request Process

1. **Update documentation** if needed
2. **Add tests** for new functionality
3. **Ensure CI passes** all checks
4. **Request review** from maintainers
5. **Address feedback** promptly

### Code Review

All contributions require code review. We review for:
- **Functionality**: Does it work as intended?
- **Security**: Are there any security implications?
- **Performance**: Impact on system resources
- **Code Quality**: Readability, maintainability
- **Testing**: Adequate test coverage

## 🏗️ Development Environment

### Prerequisites
- Linux operating system (Ubuntu 20.04+ recommended)
- Python 3.8+
- Git
- C compiler (clang)
- eBPF development tools

### Setup
```bash
# Clone and setup
git clone https://github.com/yourusername/kmim.git
cd kmim

# Install system dependencies
sudo apt update
sudo apt install -y python3-dev python3-pip libbpf-dev clang llvm

# Install Python dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Build eBPF components
cd ebpf && make all && cd ..

# Install pre-commit hooks
pre-commit install
```

### Project Structure
```
├── cli/           # Python CLI code
├── ebpf/          # eBPF kernel programs
├── tests/         # Test suite
├── docs/          # Documentation
└── .github/       # GitHub workflows
```

## 🧪 Testing

### Running Tests
```bash
# All tests
make test

# Python tests only
python -m pytest tests/ -v

# eBPF tests only
cd ebpf && make test

# Integration tests (requires root)
sudo python -m pytest tests/integration/
```

### Writing Tests
- Place tests in appropriate `tests/` subdirectories
- Use descriptive test names
- Include both positive and negative test cases
- Mock external dependencies when possible

## 📝 Documentation

### Types of Documentation
- **Code comments**: For complex algorithms
- **Docstrings**: For all public functions/classes
- **README**: User-facing documentation
- **Man pages**: Command-line reference
- **Wiki**: Detailed guides and tutorials

### Documentation Standards
- Clear, concise language
- Include examples where helpful
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting

## 🔒 Security

### Security Considerations
- KMIM runs with root privileges
- Be careful with file operations
- Validate all inputs
- Consider privilege escalation implications

### Reporting Security Issues
- **DO NOT** open public issues for security vulnerabilities
- Email security@yourdomain.com
- Include detailed description and reproduction steps
- Allow time for assessment and fix

## 📋 Release Process

### Version Numbering
We use Semantic Versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist
- [ ] Update version numbers
- [ ] Update CHANGELOG.md
- [ ] Run full test suite
- [ ] Update documentation
- [ ] Create release notes
- [ ] Tag release
- [ ] Update package repositories

## 🏷️ Issue Labels

We use the following labels to organize issues:

### Type
- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements to documentation
- `question`: Further information is requested

### Priority
- `critical`: Must be fixed immediately
- `high`: Should be fixed soon
- `medium`: Normal priority
- `low`: Nice to have

### Status
- `help-wanted`: Extra attention is needed
- `good-first-issue`: Good for newcomers
- `wontfix`: This will not be worked on

## 💬 Community

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Email**: Direct contact for security issues

### Code of Conduct
We are committed to providing a welcoming and inclusive environment. Please read our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🎉 Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to KMIM! 🚀
