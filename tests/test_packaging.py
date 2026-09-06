from pathlib import Path

import yaml


def test_makefile_includes_docker_up_and_demo_targets():
    content = Path("Makefile").read_text()
    assert "up:" in content
    assert "down:" in content
    assert "demo-local:" in content
    assert "$(COMPOSE) up --build -d $(SERVICE)" in content
    assert "$(COMPOSE) run --rm" in content


def test_docker_compose_uses_host_gateway_for_ollama():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text())
    service = compose["services"]["network-dork"]
    assert service["working_dir"] == "/workspace"
    assert ".:/workspace" in service["volumes"]
    assert "host.docker.internal:host-gateway" in service["extra_hosts"]
    assert service["environment"]["NETWORK_DORK_CONFIG"] == "/workspace/config/default.yaml"


def test_dockerfile_installs_uv_and_project_environment():
    content = Path("Dockerfile").read_text()
    assert "uv==0.12.10" in content
    assert "UV_PROJECT_ENVIRONMENT=/opt/network-dork/.venv" in content
    assert "CMD [\"sh\", \"-lc\", \"tail -f /dev/null\"]" in content


def test_ci_workflow_runs_tests_and_fake_smoke():
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())
    steps = workflow["jobs"]["test"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "make test" in commands
    assert "python -m network_dork adapters" in commands
    assert "python -m network_dork run --config config/default.yaml --fake" in commands
