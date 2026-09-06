import json

import httpx

from network_dork.adapters.alerts.opensearch import OpenSearchAlertSource
from network_dork.adapters.alerts.suricata_eve import SuricataEveAlertSource
from network_dork.adapters.alerts.zeek_notice import ZeekNoticeAlertSource


def test_suricata_eve_source_parses_only_alert_events():
    alerts = list(SuricataEveAlertSource("fixtures/source_samples/suricata/eve.json").poll())
    assert len(alerts) == 2
    assert alerts[0].source == "suricata-eve"
    assert alerts[0].title == "ET MALWARE Possible Periodic HTTP Beacon"
    assert str(alerts[0].src_ip) == "10.10.1.5"
    assert str(alerts[0].dst_ip) == "192.0.2.44"
    assert alerts[0].domains == ["callback-one.test"]
    assert alerts[1].domains == ["chunk-four.channel-four.test"]


def test_zeek_notice_source_parses_notice_records():
    alerts = list(ZeekNoticeAlertSource("fixtures/source_samples/zeek/notice.log").poll())
    assert len(alerts) == 2
    assert alerts[0].source == "zeek-notice"
    assert alerts[0].title == "SMB::Admin_Share_Access"
    assert alerts[0].host == "workstation-07.test"
    assert alerts[0].domains == ["files-seven.test"]
    assert str(alerts[1].src_ip) == "10.20.0.11"


def test_opensearch_export_source_parses_search_response_file():
    alerts = list(
        OpenSearchAlertSource(path="fixtures/source_samples/opensearch/alerts-search.json").poll()
    )
    assert len(alerts) == 2
    assert alerts[0].source == "opensearch-alerts"
    assert alerts[0].title == "Suspicious DNS tunneling"
    assert alerts[0].domains == ["mfrggzdfmztwq2lk.channel-three.test", "resolver.test"]
    assert alerts[1].domains == ["upload-five.test"]


def test_opensearch_live_source_queries_search_api():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/security-alerts-*/_search"
        payload = json.loads(request.content)
        assert payload["query"] == {"match_all": {}}
        return httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_id": "live-1",
                            "_source": {
                                "@timestamp": "2025-01-15T12:00:00Z",
                                "rule": {"name": "Live OpenSearch alert"},
                                "message": "Existing alert from a live search.",
                                "source": {"ip": "10.0.0.20"},
                                "destination": {"ip": "192.168.1.25", "domain": "live-alert.test"},
                            },
                        }
                    ]
                }
            },
        )

    source = OpenSearchAlertSource(
        base_url="http://127.0.0.1:9200",
        index="security-alerts-*",
        username="reader",
        password="secret",
        transport=httpx.MockTransport(handler),
    )
    try:
        alerts = list(source.poll())
    finally:
        source.close()
    assert len(alerts) == 1
    assert alerts[0].alert_id == "opensearch-alerts:live-1"
    assert alerts[0].domains == ["live-alert.test"]
