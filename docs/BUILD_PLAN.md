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
HTML 화면 구성은 docs/mockup/dashboard.html 시안을 따르고, 룰 메타데이터는 docs/rules-catalog.json에서 읽어.
번역할 문구는 {ko, en}으로 넣고 --lang ko|en 으로 기본 언어만 정해 (리포트 안에서 전환 가능).
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

## Phase 10. 배포와 정기 점검

목표: 처음 한 번 설정을 리뷰하고, 이후에는 **스캔은 Claude Code 밖에서 정기적으로**, Claude Code 안에서는
**"마지막 스캔이 오래됐다"는 한 줄 알림만** 받는다. 모델은 실제 설정 내용을 보지 않는다.

전제: Phase 1–8 완료 (스캐너가 실제로 동작해야 한다).

### 한눈에 보기

| 단계 | 누가 | 내용 | 완료 조건 |
|---|---|---|---|
| 10.1 | 나 → Claude | CLAUDE.md 쓰기 규칙 변경 승인 후 반영 | CLAUDE.md에 새 문구 반영 |
| 10.2 | Claude | `--out-dir`, 날짜별 리포트, `summary.json` | 테스트 통과 |
| 10.3 | Claude | `--baseline` 비교와 `changed` 표시 | 테스트 통과 |
| 10.4 | Claude | `cc-policy-lens status` 서브커맨드 | settings를 읽지 않음을 테스트로 증명 |
| 10.5 | Claude | `pyproject.toml` 진입점 | 임시 venv에서 설치·실행 성공 |
| 10.6 | Claude | LaunchAgent 템플릿과 실행 스크립트 | `plutil -lint` 통과 |
| 10.7 | Claude | CI 예시 (GitHub Actions) | YAML 문법 확인 |
| 10.8 | Claude | `docs/INSTALL.md` 설치 안내 | 아래 10.9–10.12를 그대로 따라 할 수 있음 |
| 10.9 | 나 | 설치 + 첫 스캔 + must-fix 수정 | must-fix 0건 |
| 10.10 | 나 | LaunchAgent 등록 | 설정 변경 시 알림 확인 |
| 10.11 | 나 | SessionStart Hook 등록 | 새 세션에 한 줄 상태 표시 |
| 10.12 | Claude | security-reviewer 검토 | 지적 사항 처리 |

"나" 단계는 Claude가 하지 않는다. `~/.claude/settings.json`, `~/Library/LaunchAgents/`는 이 도구가
절대 수정하지 않는 위치이고, 샌드박스도 막는다.

### 10.1 쓰기 규칙 변경 (나: 승인 → Claude: 반영)
리포트 이력과 `summary.json`을 남기려면 "쓰기는 `--out` 파일 하나뿐" 규칙을 바꿔야 한다. 제안 문구:

> 쓰기는 `--out` 파일 또는 `--out-dir` 디렉터리 안으로만 한다. `--out-dir`은 사용자 소유이고 심볼릭 링크가 아니어야 하며,
> 없으면 0700으로 만든다. 사용자의 Claude Code 설정 파일과 그 디렉터리에는 어떤 경우에도 쓰지 않는다.

승인하면:
```
CLAUDE.md의 "이 도구의 정체성" 쓰기 규칙을 BUILD_PLAN 10.1의 제안 문구로 바꿔줘.
```

### 10.2 출력 디렉터리 모드
```
scan에 --out-dir 옵션을 추가해. 동작:
- <out-dir>/reports/YYYYMMDD-HHMMSS.{html,json} 저장, <out-dir>/summary.json 갱신
- summary.json에는 설정 값을 넣지 않는다: scanned_at, tool_version, catalog_version, exit_code,
  bucket별 개수, 룰별 {id, status, severity} 만
- out-dir가 심볼릭 링크이거나 다른 사용자 소유면 거부, 없으면 0700으로 생성, 파일은 0600
- reports/ 는 최근 N개(기본 12)만 유지
```
```
/goal python3 -m unittest tests.test_outdir 가 실패 0건이고, summary.json에 설정 값이 들어가지 않음을 검사하는 테스트가 있다
```

### 10.3 이전 스캔과 비교
```
--baseline <summary.json> 옵션을 추가해 (out-dir 모드에서는 기존 summary.json이 기본값).
새로 생긴 위반, 해결된 위반, 상태가 바뀐 룰을 계산해 리포트 상단과 summary.json의 "changes"에 넣고,
변화가 있으면 "changed": true. 종료 코드 규칙(critical/high면 1)은 그대로 둔다.
```

### 10.4 status 서브커맨드
Hook과 LaunchAgent가 같이 쓰는 한 줄 출력 명령.
```
cc-policy-lens status 서브커맨드를 만들어. summary.json 하나만 읽고 설정 파일은 절대 열지 않는다.
출력 예: "cc-policy-lens: 마지막 스캔 9일 전 · must-fix 2 · ~/.cc-policy-lens/reports/…html"
옵션: --max-age-days N (기본 7, 넘으면 "스캔 필요"), --quiet-if-ok (최신이고 must-fix 0이면 아무것도 출력 안 함),
--exit-on-change (changed면 종료 코드 3). summary.json이 없으면 "아직 스캔 안 함" 안내.
```
```
/goal python3 -m unittest tests.test_status 가 실패 0건이고, status가 summary.json 외의 파일을 열지 않음을 open을 가로채서 검증하는 테스트가 있다
```

### 10.5 패키징
```
pyproject.toml을 추가해 (setuptools, 외부 의존성 없음, requires-python >=3.10).
console script 이름은 cc-policy-lens. 임시 venv에서 pip install . 후 cc-policy-lens --help가 동작하는지 확인해.
```

### 10.6 LaunchAgent 템플릿
```
examples/launchd/ 에 다음을 만들어:
- com.cc-policy-lens.scan.plist 템플릿: 매주 월요일 09:00 + WatchPaths(~/.claude/settings.json,
  /Library/Application Support/ClaudeCode/). ~/.claude.json은 Claude Code가 계속 고쳐 쓰므로 감시하지 않는다.
  경로는 __HOME__, __BIN__ 자리표시자로 두고 설치 시 사용자가 치환
- run-scan.sh: scan --out-dir 실행 → status --exit-on-change → 변화가 있을 때만 macOS 알림
  (알림은 이 스크립트가 osascript로 보낸다. 파이썬 도구 안에서는 subprocess를 쓰지 않는다)
- WatchPaths가 짧은 시간에 여러 번 울리지 않도록 ThrottleInterval 설정
설치 명령은 문서에만 적고 실행하지 마.
```

### 10.7 CI 예시
```
examples/ci/github-actions.yml 을 만들어. PR마다 cc-policy-lens scan --project . --format json 을 돌려
project 계층 룰(HOOK-001, MCP-001, MCP-002, PERM-006 등)을 점검하고, 종료 코드 1이면 실패.
리포트는 artifact로 올리되 홈 디렉터리 계층은 CI에 없다는 점을 주석으로 남겨.
```

### 10.8 설치 문서
```
docs/INSTALL.md 를 써줘. 10.9–10.11 을 순서대로 따라 할 수 있게, 복사해서 붙여넣을 명령과
되돌리는 방법(LaunchAgent 해제, Hook 제거)까지 포함해. 실제 스캔은 일반 터미널에서 하라고 명시.
```

### 10.9 첫 리뷰 (나, 일반 터미널)
```bash
pipx install git+https://github.com/safetyelliai-dotcom/cc-policy-lens
cc-policy-lens scan --project ~/work/<repo> --out-dir ~/.cc-policy-lens
open ~/.cc-policy-lens/reports/*.html
```
"반드시 수정" 열을 0으로 만들고 다시 스캔. 이때부터 summary.json이 기준선이 된다.

### 10.10 정기 점검 등록 (나)
`docs/INSTALL.md`대로 plist의 자리표시자를 치환해 `~/Library/LaunchAgents/`에 넣고 `launchctl bootstrap`.
확인: `~/.claude/settings.json`에 무해한 변경(예: 키 하나 추가 후 되돌리기)을 하면 알림이 와야 한다.

### 10.11 Claude Code 시작 시 알림 (나)
`~/.claude/settings.json`에 직접 추가 (pipx 경로는 `which cc-policy-lens`로 확인해 절대 경로로):
```json
{
  "hooks": {
    "SessionStart": [
      { "matcher": "startup",
        "hooks": [ { "type": "command", "command": "/Users/<me>/.local/bin/cc-policy-lens status --quiet-if-ok" } ] }
    ]
  }
}
```
이 Hook이 모델에 넘기는 정보는 status의 한 줄(날짜, 개수, 리포트 경로)뿐이다.
확인: 새 세션에서 `/hooks`로 등록을 보고, 스캔이 7일 넘었거나 must-fix가 있을 때 한 줄이 보이는지 확인.
(SessionStart의 matcher 값은 설치 시점 문서로 다시 확인할 것)

### 10.12 검토
```
security-reviewer 서브에이전트로 Phase 10 변경분(out-dir 쓰기, status, run-scan.sh, plist)을 검토해줘.
특히 경로 처리, 파일 권한, summary.json에 설정 값이 새는지, 셸 스크립트 인용 처리를 봐줘. 수정은 내가 확인한 뒤에.
```
