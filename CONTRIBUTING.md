# Contributing to Audio Stego Solver

Thank you for contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/example/audio-stego-solver
cd audio-stego-solver
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v --cov=audio_stego
```

## Code Style

- PEP8 / black formatting: `black audio_stego/ tests/`
- Import sorting: `isort audio_stego/ tests/`
- Type hints required on all public functions

## Adding a Plugin

1. Create `audio_stego/plugins/myplugin_plugin.py`
2. Subclass `BasePlugin` and set `name`, `version`, `author`, `description`,
   `supported_file_types`, `dependencies` (external tools/libraries you
   require — declare them even if the list is empty), `input_types`,
   `output_types`
3. Implement `run(audio_path, output_dir, results) -> dict`
4. A plugin that raises is caught per-plugin by `PluginManager` and does not
   stop the rest of the scan — you don't need your own top-level try/except
   just for that, though you should still catch expected failure modes
   (missing dependency, bad input) to return a useful partial result.
5. Add tests in `tests/`
6. Submit a PR

## Pull Request Checklist

- [ ] Tests pass: `pytest tests/ -v`
- [ ] New features have tests
- [ ] Docstrings on all public methods
- [ ] Type hints on all function signatures
- [ ] No hardcoded paths
- [ ] CHANGELOG.md updated
