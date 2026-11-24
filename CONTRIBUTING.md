# Contributing to AegisGateway

Thank you for your interest in contributing to AegisGateway!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/csenta/aegis-gateway.git
   cd aegis-gateway
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Run the automated test suite:
   ```bash
   python3 -m unittest discover -s tests -v
   ```

## Pull Request Guidelines

- Ensure all 19 unit and integration tests pass before submitting.
- If introducing a new guardrail pattern or policy rule, include corresponding test cases in `tests/`.
- Adhere to PEP 8 standards and keep methods modular.
- Update `ARCHITECTURE.md` or `API.md` if changing public endpoints or configuration schemas.
