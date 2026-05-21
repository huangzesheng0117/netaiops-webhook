# NetAIOps webhook v7.5 Skill Draft Builder Runbook

v7.5 takes approved v7.4 proposal reviews and generates draft skill packages under data/skill_drafts/.

## Safety

- Read approved reviews only.
- Write data/skill_drafts only.
- Do not write formal skills/.
- Do not auto merge.
- Do not execute MCP or device commands.

## Commands

python tools/build_skill_drafts.py --summary --validate-safety

python tools/build_skill_drafts.py --list

curl -s 'http://127.0.0.1:18080/v7/skill-drafts?limit=10' | python -m json.tool

curl -s -X POST 'http://127.0.0.1:18080/v7/skill-drafts/rebuild' | python -m json.tool

## Expected

If no proposal has been approved, draft_count=0 is normal.

After a proposal is approved in v7.4, v7.5 can generate a draft package with:

- SKILL.md
- commands.yaml
- evidence_rules.yaml
- output_schema.json
- proposal_snapshot.json
- DRAFT_STATUS.md
