# Source-format alert samples

These files are small, authored examples in source-native formats used only to
exercise alert adapters:

- `suricata/eve.json`: JSON-lines Suricata EVE events, including alert events.
- `zeek/notice.log`: JSON-lines Zeek notice records.
- `opensearch/alerts-search.json`: an exported OpenSearch `_search` response.

They are distinct from the normalized fixture corpus under `fixtures/alerts/`.
The normalized corpus feeds the investigation pipeline; these files test that
phase-6 adapters can parse source-native alert formats into the shared `Alert`
model without adding detection logic.
