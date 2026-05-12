# Building Documentation

The Insights RBAC project uses **Sphinx** to generate documentation from reStructuredText (`.rst`) files in `docs/source/`.

The project currently does NOT use Sphinx's `autodoc` extension to auto-generate API documentation from Python docstrings. All documentation is manually written in `.rst` files.

The documentation is automatically built and published to [insights-rbac.readthedocs.io](https://insights-rbac.readthedocs.io) whenever changes are pushed to the repository.


## Configuration Files

| File | Purpose |
|------|---------|
| `.readthedocs.yaml` | Read The Docs configuration (v2 format) |
| `docs/source/conf.py` | Sphinx configuration (themes, extensions) |
| `docs/rtd_requirements.txt` | Minimal RTD build dependencies (Sphinx + theme only) |
| `Pipfile` | Local dev dependencies (includes Sphinx for local builds) |
| `Makefile` | Convenience commands including `make html` |


## How It Works

**Minimal Configuration:** The documentation build requires ONLY Sphinx and the Read The Docs theme.

All documentation is manually written in `.rst` (reStructuredText) files in `docs/source/`. Sphinx converts these to HTML.

**Dependencies:**
- **For RTD builds:** `docs/rtd_requirements.txt` (2 packages - Sphinx + theme)
- **For local builds:** `Pipfile` dev-packages (includes Sphinx)


## Building Locally using Make

```bash
# Build HTML documentation
make html

# Output will be in docs/_build/html/
# Open docs/_build/html/index.html in your browser
```

## Read The Docs Build Process

When you push to GitHub, Read The Docs automatically:

1. Detects configuration (`.readthedocs.yaml`)
2. Executes build steps
3. Publishes Documentation


## Troubleshooting - Changes Not Appearing on Read The Docs
1. Check RTD build status: https://readthedocs.org/projects/insights-rbac/builds/
2. Look for build errors in the logs
3. Trigger a manual rebuild on RTD dashboard
4. Verify `.readthedocs.yaml` is at repository root


## Resources

- **Sphinx Documentation:** https://www.sphinx-doc.org/
- **Read The Docs Documentation:** https://docs.readthedocs.io/
- **reStructuredText Primer:** https://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html
- **Our Published Docs:** https://insights-rbac.readthedocs.io/
