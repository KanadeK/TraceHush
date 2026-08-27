"""Create deterministic non-wheel assets and SHA-256 checksums for a tag."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
_TIMESTAMP = (2024, 1, 2, 3, 4, 6)


def _project_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(project["version"])


def _bundle_examples(version: str) -> Path:
    output = DIST / f"tracehush-{version}-examples.zip"
    sources = [
        ROOT / "examples" / "generated" / "safe-trace.zip",
        ROOT / "examples" / "generated" / "leaky-trace.zip",
    ]
    with zipfile.ZipFile(output, "w") as archive:
        for source in sources:
            info = zipfile.ZipInfo(source.name, date_time=_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            archive.writestr(info, source.read_bytes())
    return output


def _write_checksums(assets: tuple[Path, ...]) -> Path:
    output = DIST / "SHA256SUMS"
    lines = []
    for path in sorted(assets, key=lambda item: item.name):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: package-release.py vVERSION")
    tag = sys.argv[1]
    version = _project_version()
    if tag != f"v{version}":
        raise SystemExit(f"tag {tag} does not match project version {version}")

    DIST.mkdir(exist_ok=True)
    examples = _bundle_examples(version)
    source_output = DIST / f"tracehush-{version}-source.zip"
    subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={ROOT.as_posix()}",
            "archive",
            "--format=zip",
            f"--prefix=tracehush-{version}/",
            f"--output={source_output}",
            tag,
        ],
        cwd=ROOT,
        check=True,
    )
    wheel = DIST / f"tracehush-{version}-py3-none-any.whl"
    source_distribution = DIST / f"tracehush-{version}.tar.gz"
    checksums = _write_checksums((wheel, source_distribution, examples, source_output))
    print(checksums)


if __name__ == "__main__":
    main()
