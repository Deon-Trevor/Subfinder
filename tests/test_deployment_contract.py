from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _example_keys() -> set[str]:
    assignment = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")
    return {
        match.group(1)
        for line in (ROOT / ".env.example").read_text().splitlines()
        if (match := assignment.match(line))
    }


def test_compose_uses_one_deployment_env_file() -> None:
    compose = (ROOT / "docker-compose.yml").read_text()

    assert ".env.providers" not in compose
    assert "env_file:" not in compose
    assert "URLSCAN_API_KEY: ${URLSCAN_API_KEY:-}" in compose
    assert "CTLOGS_API_TOKENS: ${CTLOGS_API_TOKENS:-}" in compose


def test_example_documents_every_interpolated_deployment_setting() -> None:
    compose = (ROOT / "docker-compose.yml").read_text()
    interpolated = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", compose))

    assert interpolated <= _example_keys()
    assert "CTLOGS_API_TOKENS" in interpolated


def test_readme_does_not_restore_the_retired_provider_file() -> None:
    readme = (ROOT / "README.md").read_text()

    assert ".env.providers" not in readme
    assert "containing `$` in single quotes" in readme


def test_edge_re_resolves_the_recreated_api_container() -> None:
    nginx = (ROOT / "deploy" / "nginx.conf").read_text()

    assert "resolver 127.0.0.11" in nginx
    assert "zone subfinder_api" in nginx
    assert "server ctlogs:8200 resolve;" in nginx
