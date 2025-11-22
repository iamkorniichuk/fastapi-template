# Setting up a project

Follow the steps below to set up your local environment.

### 1. Virtual Environment
Create and activate a virtual environment to isolate project dependencies:
```bash
virtualenv venv
source ./venv/bin/activate
```

Then, download all packages needed for running and developing the application:
```bash
pip install -r requirements.txt -r dev-requirements.txt
```

### 2. Environment Settings

Rename [example.env](/example.env) to `.env` and provide values for your project settings.

Refer to [settings file](/app/core/settings.py) for description of each variable.

### 3. Pre-commit hooks
Set up pre-commit hooks to automatically run code quality checks before each commit:
```bash
pre-commit install --install-hooks
```
