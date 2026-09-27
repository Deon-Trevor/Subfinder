from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EXPORT = load("export_r2_index_for_publish", ROOT / "scripts/export_r2_index.py")
PUBLISH = load(
    "publish_r2_generation",
    ROOT / "scripts/publish_r2_generation.py",
)


def exported(tmp_path: Path) -> Path:
    output = tmp_path / "export"
    EXPORT.export_catalog(
        __import__("test_r2_index_v2").catalog(),
        output=output,
        generation="publish-fixture",
        apexes=None,
        partition_nibbles=2,
        target_block_bytes=1_024,
    )
    return output


def test_publish_plan_validates_objects_and_stages_candidate_last(tmp_path: Path) -> None:
    plan = PUBLISH.load_publish_plan(exported(tmp_path))
    commands = PUBLISH.publish_commands(
        plan,
        bucket="catalog-test",
        wrangler=Path("/wrangler"),
        target="local",
    )

    assert plan.generation == "publish-fixture"
    assert len(plan.objects) >= 2
    assert all("/catalog/generations/publish-fixture/" in item[4] for item in commands[:-1])
    assert commands[-1][4] == "catalog-test/catalog/candidates/publish-fixture.json"
    assert commands[-1][-2:] == ["--local", "--force"]


def test_corrupt_bundle_is_rejected_before_publish(tmp_path: Path) -> None:
    output = exported(tmp_path)
    plan = PUBLISH.load_publish_plan(output)
    bundle = next(item for item in plan.objects if item.key.endswith(".bundle"))
    bundle.path.write_bytes(bundle.path.read_bytes() + b"corrupt")

    try:
        PUBLISH.load_publish_plan(output)
    except ValueError as error:
        assert "bundle size mismatch" in str(error)
    else:
        raise AssertionError("expected corrupt bundle to be rejected")


def test_execute_publish_stops_before_root_when_generation_upload_fails() -> None:
    commands = [["put", "generation-a"], ["put", "generation-b"], ["put", "root"]]
    called: list[list[str]] = []

    def runner(command, **_kwargs):
        called.append(command)
        if command[-1] == "generation-b":
            raise RuntimeError("upload failed")

    try:
        PUBLISH.execute_publish(commands, runner=runner)
    except RuntimeError as error:
        assert str(error) == "upload failed"
    else:
        raise AssertionError("expected publish failure")

    assert called == commands[:2]
