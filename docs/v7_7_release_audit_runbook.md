# NetAIOps webhook v7.7 Release Audit Runbook

v7.7 is the release and Git-cleanup precheck stage for the v7 Hermes-style sidecar.

## Scope

- Check v7.1-v7.6 files exist.
- Check v7 APIs are registered.
- Check v7 tools and regression scripts are executable.
- Check strict v7 sidecar outputs do not contain raw IPv4 or obvious secret patterns.
- Check runtime sidecar files are not tracked by Git.
- Write docs/v7_7_release_audit_snapshot.json.

## Safety

- Does not execute MCP or device commands.
- Does not write formal skills/.
- Does not auto merge.
- Does not commit Git.

## Commands

python tools/v7_release_audit.py --summary --write

bash tools/regress_v7_7.sh

bash tools/regress_v7_all.sh

bash tools/regress_v6_all.sh

curl -s 'http://127.0.0.1:18080/v7/release/audit?write=true' | python -m json.tool

## Expected

- verdict=pass
- violation_count=0
- v7 all regression PASS
- v6.6 all regression PASS
