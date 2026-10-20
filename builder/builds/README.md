# Builder CLI default output

**Role:** Default `--output ./builds` directory when running `build_implant.py` from the
`builder/` working directory.

This is a convenience path for manual or scripted builds invoked directly:

```bash
cd jager/builder
python build_implant.py --c2-url https://127.0.0.1:443 --output ./builds
```

Teamserver and harness builds normally write to `jager/data/builds/` or repo-root `builds/`
instead. Artifacts here are typically from local development smoke tests.

**Do not delete** without checking metadata JSON sidecars for active build IDs.
