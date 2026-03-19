# NetAIOps Webhook - Current Status

## Current Version
webhook_v3

## Current Architecture
The service now supports the following lifecycle:

webhook -> raw -> normalized -> analysis -> plan -> confirm -> execution -> review -> summary

## Implemented Capabilities

### 1. Webhook Ingestion
- Accept Alertmanager webhook
- Accept Elastic webhook

### 2. Data Persistence
- Save raw webhook payload
- Save normalized event data
- Save analysis result
- Save plan result
- Save execution result
- Save review result

### 3. Analysis Layer
- Async analysis processing
- Query latest analysis
- Query analysis by request_id
- Replay analysis by request_id

### 4. Plan Layer
- Generate plan from analysis
- Query latest plan
- Query plan by request_id
- Guard readonly commands
- Confirm safe readonly plan

### 5. Execution Layer
- Create execution record from confirmed plan
- Dispatch execution
- Complete execution
- Fail execution
- External execution result callback

### 6. Review Layer
- Generate review from execution result
- Query latest review
- Query review by request_id

### 7. Summary Layer
- Query one request_id across:
  - analysis
  - plan
  - execution
  - review

## Current API Endpoints

### Health
- GET /health

### Analysis
- GET /analysis/latest
- GET /analysis/{request_id}
- POST /analysis/replay/{request_id}

### Plan
- GET /plan/latest
- GET /plan/{request_id}
- POST /plan/generate/{request_id}
- POST /plan/confirm/{request_id}
- POST /plan/execute/{request_id}

### Execution
- GET /execution/latest
- GET /execution/{request_id}
- POST /execution/dispatch/{request_id}
- POST /execution/complete/{request_id}
- POST /execution/fail/{request_id}
- POST /execution/result/{request_id}

### Review
- GET /review/latest
- GET /review/{request_id}
- POST /review/generate/{request_id}

### Summary
- GET /request/{request_id}/summary

## Data Directories

- data/raw/
- data/normalized/
- data/analysis/
- data/plans/
- data/execution/
- data/reviews/

## Current Execution Mode
Execution is currently stub-based.
No real mcp-netmiko dispatch is connected yet.

## Recommended Next Phase
- Connect execution dispatcher to mcp-netmiko
- Return real command outputs into /execution/result/{request_id}
- Optionally add second-round LLM review based on execution evidence
