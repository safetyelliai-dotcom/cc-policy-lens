# 빌드 플랜 — Claude Code 단계별 프롬프트

각 단계 프롬프트를 Claude Code에 그대로 붙여넣는다. 단계마다 이번 세션에서 공부한 기능을 하나씩 의도적으로 사용한다.

## Phase 0. 세팅 확인 (학습: 설정 계층, 권한, Hooks)
세션을 열고 직접 실행:
```
/status
/permissions
/hooks
/agents
```
그리고 Hook이 동작하는지 일부러 시험:
```
tests/fixtures/tmp.txt 파일에 "AKIA" 뒤에 대문자 16개를 붙인 문자열을 써줘
```
→ guard_write Hook이 차단하면 성공. 확인 후 이 시험은 잊어도 된다.

## Phase 1. 뼈대 + 모델 (학습: CLAUDE.md, PostToolUse Hook)
```
docs/SPEC.md를 읽고 패키지 뼈대(__main__, cli, paths, model, mask)를 만들어줘.
mask 모듈과 그 테스트부터 완성해. 가짜 시크릿은 CLAUDE.md 규칙대로 런타임에 조합해.
```
```
/goal python3 -m unittest tests.test_mask 가 실패 0건으로 통과하고, cc_policy_lens 아래 모든 .py가 py_compile을 통과한다
```

## Phase 2. 수집기 (학습: /goal 종료 조건)
```
SPEC 2장대로 collect.py를 구현해. 실제 홈 디렉터리가 아니라 경로를 주입받게 만들고,
tests/fixtures/ 아래 가짜 계층 구조로 테스트해. 심볼릭 링크, 권한 없음, 거대 파일, 깨진 JSON 케이스 포함.
```
```
/goal python3 -m unittest tests.test_collect 가 실패 0건으로 통과하고, 실제 ~/.claude 경로를 읽는 테스트가 하나도 없다
```

## Phase 3. 병합기
```
SPEC 3장대로 merge.py를 구현해. 모든 값에 출처를 붙이고, 덮어써진 값은 shadowed로 보존해.
병합 규칙이 확실하지 않은 부분은 code.claude.com 문서를 확인하고, 확인 못 한 부분은 주석과 TODO로 남겨.
```
```
/goal python3 -m unittest tests.test_merge 가 실패 0건으로 통과한다
```

## Phase 4. 룰 엔진 (학습: 스킬)
```
write-check-rule 스킬 절차대로 docs/RULES.md의 CFG, PERM, SBX 룰부터 구현해.
```
이어서 HOOK, MCP, PLG, WF, AGT, ENV, VER 룰을 같은 방식으로 반복.
```
/goal docs/RULES.md의 모든 룰이 done 이상이고, python3 -m unittest discover -s tests 전체가 실패 0건으로 통과한다
```

## Phase 5. 리포트
```
report/ 아래 json, md, html 렌더러를 만들어. HTML은 단일 파일, 외부 리소스 없음,
모든 설정값은 html.escape를 거쳐. 다크 모드 지원. 종료 코드는 SPEC 5장대로.
```

## Phase 6. 보안 자체 검토 (학습: 서브에이전트)
```
security-reviewer 서브에이전트로 cc_policy_lens/ 전체를 검토하고 결과를 요약해줘. 수정은 내가 확인한 뒤에.
```

## Phase 7. 룰 교차 검증 (학습: 워크플로우) — 선택
토큰을 많이 쓰므로 `/config`에서 Dynamic workflow size를 small로 두고 시작.
```
use a workflow to verify each rule in docs/RULES.md: for each rule, one agent reads the rule
and its implementation and tries to construct a fixture that produces a false negative or false positive.
Then adversarially verify each claimed issue before reporting. Do not modify code.
```

## Phase 8. 도그푸딩 (일반 터미널에서)
Claude Code 밖, 일반 터미널에서:
```bash
python3 -m cc_policy_lens scan --project . --format html --out report.html
```
이 레포 자체를 스캔하면 project 계층의 Hooks(HOOK-001), allow 규칙(PERM-006) 등이 잡혀야 한다.
리포트에 시크릿 원문이 없는지 직접 확인.

## Phase 9. (선택) 개인 managed 설정으로 계층 테스트
`examples/managed-settings.personal.json`을 managed 경로에 설치한 뒤 다시 스캔해서
managed 계층이 수집, 병합되는지 확인.
