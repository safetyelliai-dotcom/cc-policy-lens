# 점검 룰 명세 (v0)

> 설정 키 이름은 구현 단계에서 공식 문서로 확인한다. 확인 전에는 `verified=false`.

| ID | 심각도 | 판정 조건 | 상태 |
|---|---|---|---|
| CFG-001 | critical | managed-settings.json이 일반 사용자에게 쓰기 가능 (소유자가 root가 아니거나 group/other 쓰기 권한) | todo |
| CFG-002 | high | managed-settings.json이 존재하지만 JSON 파싱 실패 | todo |
| PERM-001 | critical | 어느 계층이든 `permissions.defaultMode`가 `bypassPermissions` | todo |
| PERM-002 | high | `permissions.disableBypassPermissionsMode`가 `"disable"`이 아님 | todo |
| PERM-003 | high | 민감 경로(.env, *.pem, ~/.ssh, ~/.aws) Read deny 누락 | todo |
| PERM-004 | high | allow에 `Bash` 또는 `Bash(*)` 같은 광범위 규칙 | todo |
| PERM-005 | medium | allow에 네트워크 도구(curl, wget, nc) | todo |
| PERM-006 | medium | project 계층이 allow 규칙을 추가함 (레포를 통한 권한 확대) | todo |
| SBX-001 | high | 샌드박스 비활성 | todo |
| HOOK-001 | medium | project/플러그인/스킬 계층에 Hook 존재 (공급망 검토 대상 목록화) | todo |
| HOOK-002 | medium | PreToolUse/PermissionRequest 정책성 Hook에 `onFailure: "block"` 없음 | todo |
| HOOK-003 | high | Hook 명령에 네트워크 전송 패턴(curl, wget, nc, http URL) | todo |
| HOOK-004 | medium | SessionStart/Setup Hook이 `CLAUDE_ENV_FILE`에 기록 | todo |
| HOOK-005 | medium | HTTP Hook이 있는데 `allowedHttpHookUrls` 미설정 | todo |
| HOOK-006 | info | `allowManagedHooksOnly` 미설정 | todo |
| MCP-001 | medium | project `.mcp.json`에 MCP 서버 정의 (레포를 통한 MCP 추가) | todo |
| MCP-002 | high | stdio MCP가 `npx`/`uvx` 등으로 실행되면서 버전 고정 없음 | todo |
| MCP-003 | high | MCP 서버 env/headers에 시크릿 원문 | todo |
| PLG-001 | medium | `strictKnownMarketplaces` 미설정 | todo |
| PLG-002 | info | 활성 플러그인 중 Hooks나 MCP 서버를 포함한 것 목록 | todo |
| WF-001 | info | 레포에 `.claude/workflows/` 스크립트 존재 (검토 대상) | todo |
| AGT-001 | medium | 서브에이전트 frontmatter에 Hook 정의 | todo |
| ENV-001 | high | settings의 `env`에 시크릿 원문 | todo |
| VER-001 | low | managed에 최소 버전 요구 설정 없음 | todo |

상태: todo → done → verified (공식 문서로 키 확인 완료)
