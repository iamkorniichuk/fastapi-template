# Setting up a Development environment

Follow the steps below to set up your local development environment.

### 1. Virtual environment
Create and activate a virtual environment to isolate project dependencies:
```bash
virtualenv venv
source ./venv/bin/activate
```

### 2. Development packages
Download all development packages listed in [requirements](/dev-requirements.txt):
```bash
pip install -r dev-requirements.txt
```

### 3. Pre-commit hooks
Set up pre-commit hooks to automatically run code quality checks before each commit:
```bash
pre-commit install --install-hooks
```
