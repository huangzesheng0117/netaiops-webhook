# NetAIOps Webhook - Current Status

## Current Version
webhook_v2.1-stable

## Current Capabilities
- Accept Alertmanager webhook
- Accept Elastic webhook
- Normalize incoming events
- Save raw / normalized / analysis JSON files
- Run async analysis in background task
- Support mock LLM mode
- Support replay analysis by request_id
- Support query latest analysis
- Support query analysis by request_id
- Support config flags:
  - analysis.save_prompt
  - analysis.save_result
- Support rotating log file
- Provide regression test samples and test script

## Current Endpoints
- GET /health
- GET /analysis/latest
- GET /analysis/{request_id}
- POST /analysis/replay/{request_id}
- POST /webhook/alertmanager
- POST /webhook/elastic

## Current Test Samples
### Alertmanager
- interface_down.json
- ospf_neighbor_down.json
- bgp_neighbor_down.json

### Elastic
- interface_down_log.json
- bgp_neighbor_down_log.json

## Next Phase
- Connect real LLM endpoint
- Validate JSON output stability
- Tune prompt and model selection
- Prepare command_plan field for future mcp-netmiko integration
