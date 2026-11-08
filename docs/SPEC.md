# cc-policy-lens 명세

## 1. 목적
Claude Code의 흩어진 설정을 모아, **실제로 적용되는 최종 설정**과 **그 출처**를 보여주고, 보안 리스크를 판정한다. 관리자가 아닌 검토자도 근거 있는 의견을 낼 수 있게 하는 것이 목표.

## 2. 수집 대상 (macOS 기준, 다른 OS 경로는 상수로 분리)

| 계층 | 경로 | 비고 |
|---|---|---|
| managed (파일) | `/Library/Application Support/ClaudeCode/managed-settings.json` | 파일 권한(소유자, 쓰기 권한)도 수집 |
| managed (MDM/서버) | 로컬 파일로 확인 불가 | `unknown`으로 표시하고 `/status`로 확인하라고 안내 |
| user | `~/.claude/settings.json` | |
| user (레거시/상태) | `~/.claude.json` | MCP 서버 정의 포함 가능, OAuth 등 민감 정보 → 필요한 키만 추출, 나머지 무시 |
| project | `<repo>/.claude/settings.json` | 레포에 커밋되는 파일 = 공급망 경로 |
| local | `<repo>/.claude/settings.local.json` | |
| project MCP | `<repo>/.mcp.json` | |
| subagents | `~/.claude/agents/`, `<repo>/.claude/agents/` | frontmatter의 tools, hooks |
| skills | `~/.claude/skills/`, `<repo>/.claude/skills/` | frontmatter의 hooks |
| workflows | `~/.claude/workflows/`, `<repo>/.claude/workflows/` | 목록만 |
| plugins | `~/.claude/plugins/` | 구성요소(hooks, MCP, agents) 목록 |

Linux: `/etc/claude-code/managed-settings.json`, Windows: `C:\Program Files\ClaudeCode\managed-settings.json`.

> 경로와 구조는 구현 시 공식 문서로 재확인할 것. 확인 못 한 경로는 수집하되 `verified=false`.

## 3. 병합 규칙
- 스칼라 값 우선순위: managed > local > project > user
- 배열(`permissions.allow/ask/deny` 등): 모든 계층을 합치고 중복 제거
- 모든 값에 **출처(계층, 파일 경로)** 를 붙인다. 덮어써진 값도 "shadowed"로 보존해 리포트에 보여준다
- 병합 규칙 자체가 버전에 따라 다를 수 있으므로 `merge.py` 한 곳에 모은다

## 4. 아키텍처

```
cc_policy_lens/
  __main__.py      # python3 -m 진입점
  cli.py           # argparse: scan --project --format {html,json,md} --out
  paths.py         # OS별 경로 상수
  collect.py       # 계층별 파일 읽기 (읽기 전용, 크기 제한, 권한/심링크 처리)
  merge.py         # 유효 설정 계산 + 출처 추적
  mask.py          # 시크릿 마스킹
  model.py         # dataclass: Layer, Source, EffectiveConfig, Finding
  rules/           # 룰 메타데이터 + 판정 함수
  report/          # html, json, md 렌더러 (HTML은 반드시 이스케이프)
```

## 5. 출력
- 요약: 계층별 존재 여부, 심각도별 finding 수
- 유효 설정 표: 키, 최종 값(마스킹), 출처, 덮어써진 값
- Findings: 심각도 순, 각 항목에 근거와 조치 방법
- Unknown: 확인 불가 항목과 수동 확인 방법 (`/status`, `/permissions`, `/hooks`)
- 종료 코드: critical/high 있으면 1, 없으면 0 (CI 활용)

## 6. 비기능 요구
- 읽기 전용, 오프라인, 표준 라이브러리만
- 파일 크기 상한(예: 5MB), JSON 중첩 상한
- 어떤 입력에도 크래시 없이 부분 결과 + 오류 목록 출력
