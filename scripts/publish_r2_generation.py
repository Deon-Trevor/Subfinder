from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


FORMAT = "subfinder.r2-index.v2"
ROOT_KEY = "catalog/root.json"


@dataclass(frozen=True)
class PublishObject:
    key: str
    path: Path
    sha256: str
    content_type: str
    cache_control: str


@dataclass(frozen=True)
class PublishPlan:
    generation: str
    objects: tuple[PublishObject, ...]
    root: PublishObject


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _object_path(output: Path, key: str) -> Path:
    if not key or key.startswith("/"):
        raise ValueError(f"catalog object key is unsafe: {key!r}")
    path = (output / key).resolve()
    if not path.is_relative_to(output.resolve()):
        raise ValueError(f"catalog object key is unsafe: {key!r}")
    if not path.is_file():
        raise ValueError(f"catalog object is missing: {key}")
    return path


def _range_metadata(index: dict[str, Any]) -> list[dict[str, Any]]:
    ranges = list(index.get("blocks", []))
    for overflow in index.get("overflow", {}).values():
        ranges.extend(overflow.get("chunks", []))
    return ranges


def _validate_ranges(bundle: Path, ranges: list[dict[str, Any]]) -> None:
    size = bundle.stat().st_size
    with bundle.open("rb") as source:
        for metadata in ranges:
            offset = int(metadata["offset"])
            length = int(metadata["length"])
            if offset < 0 or length < 1 or offset + length > size:
                raise ValueError(f"catalog block range is invalid: {bundle}")
            source.seek(offset)
            compressed = source.read(length)
            if hashlib.sha256(compressed).hexdigest() != metadata["sha256"]:
                raise ValueError(f"catalog block checksum mismatch: {bundle}")
            try:
                gzip.decompress(compressed)
            except (EOFError, OSError) as error:
                raise ValueError(f"catalog block is not valid gzip: {bundle}") from error


def load_publish_plan(output: Path) -> PublishPlan:
    output = output.resolve()
    root_path = _object_path(output, ROOT_KEY)
    try:
        root = json.loads(root_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("catalog root is not valid JSON") from error
    if root.get("format") != FORMAT:
        raise ValueError("catalog root format is unsupported")
    generation = root.get("generation")
    if not isinstance(generation, str) or not generation:
        raise ValueError("catalog generation is missing")
    generation_prefix = f"catalog/generations/{generation}/"

    objects: list[PublishObject] = []
    seen: set[str] = set()
    for prefix, metadata in sorted(root.get("partitions", {}).items()):
        index_key = str(metadata["index"])
        bundle_key = str(metadata["bundle"])
        if not index_key.startswith(generation_prefix) or not bundle_key.startswith(
            generation_prefix
        ):
            raise ValueError("catalog partition points outside its generation")
        if index_key in seen or bundle_key in seen:
            raise ValueError("catalog object key is duplicated")
        seen.update({index_key, bundle_key})

        index_path = _object_path(output, index_key)
        compressed_index = index_path.read_bytes()
        index_sha256 = hashlib.sha256(compressed_index).hexdigest()
        if index_sha256 != metadata["index_sha256"]:
            raise ValueError(f"partition index checksum mismatch: {index_key}")
        try:
            index = json.loads(gzip.decompress(compressed_index))
        except (EOFError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(f"partition index is invalid: {index_key}") from error
        if (
            index.get("format") != FORMAT
            or index.get("generation") != generation
            or index.get("prefix") != prefix
            or index.get("bundle") != bundle_key
        ):
            raise ValueError(f"partition index identity mismatch: {index_key}")

        bundle_path = _object_path(output, bundle_key)
        if bundle_path.stat().st_size != int(metadata["bundle_bytes"]):
            raise ValueError(f"partition bundle size mismatch: {bundle_key}")
        bundle_sha256 = file_sha256(bundle_path)
        if bundle_sha256 != metadata.get("bundle_sha256"):
            raise ValueError(f"partition bundle checksum mismatch: {bundle_key}")
        _validate_ranges(bundle_path, _range_metadata(index))

        objects.extend(
            [
                PublishObject(
                    key=bundle_key,
                    path=bundle_path,
                    sha256=bundle_sha256,
                    content_type="application/octet-stream",
                    cache_control="public, max-age=31536000, immutable",
                ),
                PublishObject(
                    key=index_key,
                    path=index_path,
                    sha256=index_sha256,
                    content_type="application/gzip",
                    cache_control="public, max-age=31536000, immutable",
                ),
            ]
        )

    return PublishPlan(
        generation=generation,
        objects=tuple(objects),
        root=PublishObject(
            key=f"catalog/candidates/{generation}.json",
            path=root_path,
            sha256=file_sha256(root_path),
            content_type="application/json",
            cache_control="no-cache",
        ),
    )


def publish_commands(
    plan: PublishPlan,
    *,
    bucket: str,
    wrangler: Path,
    target: str,
) -> list[list[str]]:
    if target not in {"local", "remote"}:
        raise ValueError("target must be local or remote")
    commands = []
    for item in (*plan.objects, plan.root):
        commands.append(
            [
                str(wrangler),
                "r2",
                "object",
                "put",
                f"{bucket}/{item.key}",
                "--file",
                str(item.path),
                "--content-type",
                item.content_type,
                "--cache-control",
                item.cache_control,
                f"--{target}",
                "--force",
            ]
        )
    return commands


def execute_publish(
    commands: Sequence[Sequence[str]],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    for command in commands:
        runner(list(command), check=True, text=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate and stage an immutable Subfinder R2 candidate; never activates it"
    )
    parser.add_argument("--export-root", required=True, type=Path)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--wrangler", required=True, type=Path)
    parser.add_argument("--target", choices=("local", "remote"), default="local")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    plan = load_publish_plan(args.export_root)
    commands = publish_commands(
        plan,
        bucket=args.bucket,
        wrangler=args.wrangler,
        target=args.target,
    )
    summary = {
        "generation": plan.generation,
        "immutable_object_count": len(plan.objects),
        "root_key": plan.root.key,
        "candidate_uploaded_last": commands[-1][4].endswith(
            f"/catalog/candidates/{plan.generation}.json"
        ),
        "target": args.target,
        "execute": args.execute,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.execute:
        execute_publish(commands)


if __name__ == "__main__":
    main()
