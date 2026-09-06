import pytest

from network_dork.config import (
    LocalEndpointError,
    resolve_local_endpoint,
)

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434",
        "http://10.0.0.5:11434",
        "http://172.16.0.5:11434",
        "http://192.168.1.5:11434",
        "http://[::1]:11434",
        "https://[fd00::5]:11434",
    ],
)
def test_permitted_numeric_endpoints(url):
    resolved = resolve_local_endpoint(url)
    assert resolved.connect_url == url

@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8:11434",
        "http://192.0.2.1:11434",
        "http://100.64.0.1:11434",
        "http://169.254.169.254",
        "http://0.0.0.0:11434",
        "http://224.0.0.1",
        "http://[::]",
        "http://[2001:4860:4860::8888]",
        "http://[fe80::1]",
        "http://[::ffff:127.0.0.1]",
        "http://user:secret@127.0.0.1:11434",
        "http://127.0.0.1:11434/api/chat",
        "http://127.0.0.1:11434?target=other",
        "http://127.0.0.1:11434#fragment",
        "http://127.0.0.1:0",
        "ftp://127.0.0.1",
        "http://127.0.0.1:99999",
        "http://127.0.0.1\\@8.8.8.8",
        " http://127.0.0.1",
        "http://[fe80::1%eth0]",
    ],
)
def test_disallowed_endpoint_categories(url):
    with pytest.raises(LocalEndpointError):
        resolve_local_endpoint(url)

def test_localhost_resolves_without_hosts_or_dns(tmp_path, monkeypatch):
    import socket

    def forbidden_dns(*args, **kwargs):
        raise AssertionError("DNS must not be used")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_dns)
    endpoint = resolve_local_endpoint(
        "http://localhost:11434",
        hosts_path=tmp_path / "does-not-exist",
    )
    assert endpoint.connect_url == "http://127.0.0.1:11434"
    assert endpoint.host_header == "localhost:11434"

def test_hosts_entry_pins_numeric_connection(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "127.0.0.1 localhost\n"
        "172.18.0.1 host.docker.internal ollama.lan # local gateway\n"
    )
    endpoint = resolve_local_endpoint(
        "http://ollama.lan:11434", hosts_path=hosts
    )
    assert endpoint.connect_url == "http://172.18.0.1:11434"
    assert endpoint.host_header == "ollama.lan:11434"
    assert endpoint.server_hostname == "ollama.lan"

def test_missing_hostname_never_falls_back_to_dns(tmp_path, monkeypatch):
    import socket

    def forbidden_dns(*args, **kwargs):
        raise AssertionError("DNS must not be used")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_dns)
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    with pytest.raises(LocalEndpointError, match="DNS lookup is disabled"):
        resolve_local_endpoint(
            "http://outside.example:11434", hosts_path=hosts
        )

def test_mixed_local_and_public_hosts_entries_are_rejected(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "10.0.0.5 ollama.lan\n"
        "8.8.8.8 ollama.lan\n"
    )
    with pytest.raises(LocalEndpointError):
        resolve_local_endpoint(
            "http://ollama.lan:11434", hosts_path=hosts
        )
