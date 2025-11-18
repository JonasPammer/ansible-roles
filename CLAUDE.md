# CLAUDE.md

## Project Overview

This is a **meta-repository management system** for maintaining JonasPammer's 11 Ansible roles. It provides centralized automation for documentation generation, dependency visualization, template synchronization (via cruft), bot PR merging, and GitHub repository settings management.

**Key Concept**: This repository doesn't contain Ansible roles itself—it manages them. The source of truth for which repositories are managed is `all-repos-in.json`.

## Essential Commands

### Initial Setup

```bash
# Clone and install
git clone git@github.com:JonasPammer/ansible-roles.git
cd ansible-roles
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
pip3 install -e .

# Optional dev dependencies
pip3 install -r requirements-dev.txt

# Configure all-repos (required for multi-repo operations)
cp all-repos.example.json all-repos.json
nano all-repos.json  # Fill in 'EDIT_ME' placeholders
chmod 600 all-repos.json

# Configure GitHub token (required for scripts)
# Create token at https://github.com/settings/tokens/new with:
#   - public_repo (required)
#   - workflow (for merge_bot_pull_requests)
# Then create .env file:
echo "GITHUB_TOKEN=your_token_here" > .env
```

### Core CLI Commands

```bash
# Generate documentation and dependency graphs
ansible-roles

# Update all roles from cookiecutter template
ansible-roles-cruft [--push]

# Merge bot PRs (pre-commit.ci, dependabot, renovate)
ansible-roles-merge_bot_pull_requests

# Sync GitHub repository metadata and settings
ansible-roles-sync_meta

# Update GitHub GALAXY_API_KEY secret
ansible-roles-sync_meta --galaxy
```

### Pre-Script Requirement

**ALWAYS** run before any maintenance command (may need multiple attempts on network timeout):

```bash
all-repos-clone
```

This clones/pulls all repositories defined in `all-repos-in.json` into `./all-repos/`.

### Code Quality

```bash
# Run pre-commit hooks
pre-commit run --all-files

# Type checking
mypy ansible_roles ansible_roles_scripts

# Run tests (if any exist)
pytest
```

## Architecture

### Data Flow

1. **Source of Truth**: `all-repos-in.json` lists all 11 managed Ansible role repositories
2. **Data Fetching**: Scripts use GitHub API + Ansible Galaxy API to fetch live metadata
3. **Caching**: API responses cached in `.ansible_roles_diskcache/` (30-min expiry)
4. **Template Rendering**: Jinja2 templates generate README.adoc and Graphviz .dot files
5. **Automation**: GitHub Actions runs daily (5am UTC) to regenerate and publish to gh-pages

### Core Abstractions

#### `AnsibleRole` Dataclass (`ansible_roles/utils.py`)

Central data model representing an Ansible role with:

- **Properties**: `repo_name`, `repo_pull_url`, `galaxy_owner`
- **Fetched Data**: `requirements_yml`, `meta_yml`, `ansible_roles_yml`, `id` (Galaxy)
- **Computed**: `computed_dependencies` (list of role dependencies)
- **Utility Methods**:
  - `role_name`: strips "ansible-role-" prefix
  - `galaxy_role_name`: returns "jonaspammer.{role_name}"
  - `get_dependency_color()`: 24-color gradient based on dependency depth

#### Module-Level Globals (`ansible_roles/utils.py`)

- `github_api`: Initialized GitHub API client (tries `GITHUB_TOKEN` env → `all-repos.json` → unauthenticated)
- `all_roles`: Dict[galaxy_role_name, AnsibleRole] - populated by `init_all_roles()`

#### Script Utilities (`ansible_roles_scripts/script_utils.py`)

- `ProcedureResultRole`/`ProcedureResultGenericRepo`: Track operation results per repository
- `execute()`: Command executor with error handling and logging
- `check_conflict_files()`: Detect unresolved git conflicts
- `is_path_ansible_role()`: Validates if directory is cruft'ed from cookiecutter-ansible-role

### Dependency Management

Two types of dependencies tracked:

1. **Soft Dependencies** (`requirements.yml`): Optional roles used in CI tests
2. **Hard Dependencies** (`meta/main.yml`): Required role dependencies

The system computes transitive dependencies and generates:

- `graphs/dependencies_ALL.{dot,png,svg}`: All-role dependency graph
- `graphs/dependencies_{role}.{dot,png,svg}`: Per-role dependency graphs

Colors indicate dependency depth (green → yellow → orange → red → purple → blue → cyan).

### Multi-Repository Operations

Uses `all-repos` tool pattern:

1. Clone all repos to `./all-repos/` (gitignored)
2. Iterate over cloned directories
3. Perform operations (git, cruft, pre-commit)
4. Optional push changes

Scripts filter repositories via:

- `get_all_cloned_github_repositories()`: Any GitHub repo in all-repos/
- `get_all_cloned_ansible_repositories()`: Only cruft'ed Ansible roles

## Important Implementation Details

### GitHub API Token Hierarchy

Scripts try to source token in order:

1. `GITHUB_TOKEN` environment variable (or `.env` file)
2. `all-repos.json` → `push_settings.api_key`
3. Unauthenticated (rate-limited)

Check `utils.github_api_used_token` to see which was used.

### Generated vs Source Files

**NEVER edit these files** (regenerated by CI):

- `README.adoc` (from `templates/README.adoc.jinja2`)
- All files in `graphs/` directory

**Source files** to edit:

- `templates/*.jinja2`
- `all-repos-in.json`
- `ansible_roles/*.py`
- `ansible_roles_scripts/*.py`

### Python Version Requirement

Requires **Python 3.10+** (see `setup.cfg` → `python_requires`)

### Bot PR Merging Logic

`ansible-roles-merge_bot_pull_requests` only merges PRs when:

1. Author is `pre-commit-ci[bot]`, `dependabot[bot]`, or `renovate[bot]`
2. All CI checks have passed
3. Bot identity verified to prevent fake PRs

### Cruft Update Workflow

`ansible-roles-cruft` performs:

1. Run `cruft update` for each role
2. Execute `pre-commit run --all-files` to format changes
3. Detect and report merge conflicts/rejected updates
4. Optionally push with `--push` flag

If conflicts occur, user must manually resolve in `./all-repos/{repo}/`, then re-run.

### Logging Verbosity

All commands support:

- `-s/--silent`: Disable console output
- `-v`: VERBOSE level
- `-vv`: DEBUG level
- `-vvv`: SPAM level (extremely detailed)

Uses `rich` for formatted console output and `verboselogs` for extended log levels.

## Configuration Files

- **`.pre-commit-config.yaml`**: Pre-commit hooks (Python formatters, linters, commitlint, prettier, yamllint)
- **`setup.cfg`**: Python package metadata, mypy config, coverage config, entry points
- **`.yamllint`**: YAML linting rules
- **`.github/workflows/gh-pages.yml`**: Main automation workflow (regenerate docs daily)
- **`.github/labels.yml`**: Label definitions synced to all repos

## Testing

Testing is minimal in this repository. The CI workflow in `.github/workflows/gh-pages.yml` serves as the primary integration test by:

1. Installing dependencies
2. Running `ansible-roles` command
3. Generating graphs
4. Committing results
5. Publishing to GitHub Pages

If generation succeeds, the system is considered functional.

## Common Pitfalls

1. **Forgetting `all-repos-clone`**: Scripts operate on locally cloned repos, not remote
2. **Editing generated files**: README.adoc and graphs/ are regenerated—edit templates instead
3. **Missing GitHub token**: Most scripts require authentication for API access
4. **Network timeouts**: `all-repos-clone` may fail; retry multiple times
5. **Merge conflicts in cruft update**: Must be resolved manually in `./all-repos/` directory
