# 점검 룰 명세 (v0.1)

> 이 문서는 `docs/rules-catalog.json`에서 생성한다. 내용을 고칠 때는 JSON을 먼저 고치고 표를 다시 만든다.
> 마지막 근거 검토: 2026-11-08. 공식 문서 기준 URL: `https://code.claude.com/docs/en/`

## 요약

- 룰 24개 · level L1 4 / L2 14 / L3 6
- 심각도 critical 2 / high 8 / medium 10 / low 1 / info 3
- 근거 incident 5 / official 18 / expert 1
- verified=false: CFG-001, MCP-002

level 기준: L1 = 실제 사고(incident) 근거가 있는 우선 점검 룰, L2 = 위협 프레임워크/공식 문서 근거, L3 = 조직 통제(managed 정책) 성격

## 룰 목록

| ID | 제목 | 영역 | Level | 심각도 | 근거 | 확인 | OWASP ASI | 사고 | 상태 |
|---|---|---|---|---|---|---|---|---|---|
| CFG-001 | managed 설정 파일을 일반 사용자가 수정할 수 있음 | config-integrity | L3 | critical | expert | ⚠️ | ASI03 | — | done |
| CFG-002 | managed 설정 파일이 JSON 객체로 파싱되지 않음 | config-integrity | L3 | medium | official | ✅ | ASI08 | — | done |
| PERM-001 | 기본 권한 모드가 bypassPermissions | permissions | L2 | critical | official | ✅ | ASI02, ASI03 | — | done |
| PERM-002 | bypassPermissions 모드 잠금(disableBypassPermissionsMode) 미설정 | permissions | L3 | high | official | ✅ | ASI03 | — | done |
| PERM-003 | 민감 경로에 대한 Read deny 규칙 누락 | permissions | L2 | high | official | ✅ | ASI01, ASI02 | — | done |
| PERM-004 | 모든 Bash 명령을 허용하는 광범위 allow 규칙 | permissions | L2 | high | official | ✅ | ASI02, ASI05 | — | done |
| PERM-005 | 네트워크 도구(curl, wget, nc 등)를 allow | permissions | L2 | medium | official | ✅ | ASI02, ASI01 | — | done |
| PERM-006 | 레포의 공유 설정(.claude/settings.json)이 allow 규칙을 추가함 | permissions | L2 | medium | official | ✅ | ASI04, ASI03 | — | done |
| SBX-001 | Bash 샌드박스 비활성 또는 실패 시 무방비 실행 | sandbox | L2 | high | official | ✅ | ASI05, ASI02 | — | done |
| HOOK-001 | 레포, 플러그인, 스킬, 서브에이전트에서 온 Hook (공급망 검토 대상) | hooks | L1 | medium | incident | ✅ | ASI04, ASI05 | CVE-2025-59536 | done |
| HOOK-002 | 정책 Hook(PreToolUse/PermissionRequest)이 실패하면 그냥 통과함(fail open) | hooks | L2 | medium | official | ✅ | ASI02, ASI08 | — | done |
| HOOK-003 | Hook 명령에 네트워크 전송 패턴 포함 | hooks | L1 | high | incident | ✅ | ASI04, ASI05, ASI02 | CVE-2025-59536 | done |
| HOOK-004 | Hook이 CLAUDE_ENV_FILE에 기록 (이후 모든 Bash 명령 앞에 실행됨) | hooks | L2 | medium | official | ✅ | ASI05, ASI06 | — | done |
| HOOK-005 | HTTP Hook이 있는데 전송 URL 허용 목록(allowedHttpHookUrls) 미설정 | hooks | L2 | medium | official | ✅ | ASI02, ASI04 | — | done |
| HOOK-006 | managed Hook만 허용(allowManagedHooksOnly) 미설정 | hooks | L3 | info | official | ✅ | ASI04 | — | done |
| MCP-001 | 레포의 .mcp.json이 MCP 서버를 정의함 | mcp | L1 | medium | incident | ✅ | ASI04, ASI05 | CVE-2025-59536 | done |
| MCP-002 | stdio MCP 서버를 버전 고정 없이 패키지 러너로 실행 | mcp | L1 | high | incident | ⚠️ | ASI04 | postmark-mcp-backdoor | done |
| MCP-003 | MCP 서버 env/headers에 시크릿 원문 | mcp | L2 | high | official | ✅ | ASI03 | — | done |
| PLG-001 | 플러그인 마켓플레이스 허용 목록(strictKnownMarketplaces) 미설정 | plugins | L3 | medium | official | ✅ | ASI04 | — | done |
| PLG-002 | 활성 플러그인 중 실행 코드(Hook, MCP, monitor, mod, bin/)를 포함한 것 | plugins | L2 | info | official | ✅ | ASI04, ASI05 | — | done |
| WF-001 | 레포에 동적 워크플로우 스크립트(.claude/workflows/*.js) 존재 | workflows | L2 | info | official | ✅ | ASI01, ASI04 | — | done |
| AGT-001 | 서브에이전트 frontmatter에 Hook, 인라인 MCP, 권한 모드 정의 | agents | L2 | medium | official | ✅ | ASI04, ASI05 | — | done |
| ENV-001 | settings의 env에 시크릿 원문 | env | L2 | high | official | ✅ | ASI03 | — | done |
| VER-001 | managed에 최소 실행 버전(requiredMinimumVersion) 미설정 | version | L3 | low | incident | ✅ | ASI04 | CVE-2025-59536, CVE-2026-21852 | done |

상태: todo → done → verified (공식 문서로 키 확인 완료). 확인 열의 ⚠️는 verified=false.

## 판정 조건과 근거

### CFG-001 · managed 설정 파일을 일반 사용자가 수정할 수 있음

- **판정**: OS별 managed 디렉터리(macOS: /Library/Application Support/ClaudeCode/, Linux·WSL: /etc/claude-code/)의 managed-settings.json, managed-settings.d/*.json, managed-mcp.json 각각에 대해 os.stat 결과가 st_uid != 0 이거나 (st_mode & 0o022) != 0 이면 위반. 상위 디렉터리도 같은 기준으로 확인. Windows(C:\Program Files\ClaudeCode\)는 ACL을 표준 라이브러리로 판정할 수 없으므로 unknown
- **공식 문서**: [managed-settings#deploy-a-managed-settings-file](https://code.claude.com/docs/en/managed-settings#deploy-a-managed-settings-file)
- **위협**: ASI03 Identity & Privilege Abuse
- **메모**: 파일 경로 3종과 managed-settings.d/, managed-mcp.json은 공식 문서로 확인. 다만 문서에는 소유자나 권한 비트 요구사항이 없고, '로컬 관리자 권한이 있는 개발자는 managed 소스를 직접 수정할 수 있다'는 설명만 있음. 판정 기준(root 소유, group/other 쓰기 금지)은 전문가 판단이라 verified=false. 초안 대비: 점검 대상을 managed-settings.json 하나에서 drop-in 디렉터리와 managed-mcp.json까지 넓힘. WSL에서는 문서상 /etc/claude-code가 사용자 쓰기 가능하므로 위반이 기본값일 수 있음. level: 조직 정책 무결성 통제라 L3. 심각도는 정책 전체 무력화로 이어지므로 critical 유지

### CFG-002 · managed 설정 파일이 JSON 객체로 파싱되지 않음

- **판정**: managed-settings.json 또는 managed-settings.d/*.json이 존재하는데 json.loads가 실패하거나 최상위가 object가 아니면 위반. 빈 파일은 문서상 {}로 취급하므로 위반 아님. 읽기 권한이 없으면 finding이 아니라 unknown
- **공식 문서**: [managed-settings#find-entries-claude-code-dropped](https://code.claude.com/docs/en/managed-settings#find-entries-claude-code-dropped)
- **위협**: ASI08 Cascading Failures
- **메모**: 공식 문서 기준 managed 파일이나 drop-in 파일이 JSON 객체로 파싱되지 않으면 Claude Code가 시작을 거부함(fail closed). 정책이 조용히 꺼지는 위험이 아니라 전체 사용자 세션이 멈추는 가용성 문제이므로 초안의 high를 medium으로 낮춤. 초안 대비: 판정 조건에 '최상위가 object가 아님'을 추가하고 빈 파일 예외를 명시. 별도로, OS가 읽기를 거부하면 해당 소스 정책 없이 세션이 시작된다는 문서 설명이 있음(추가 룰 제안 참고). level: 조직 정책 운영 통제라 L3

### PERM-001 · 기본 권한 모드가 bypassPermissions

- **판정**: user, managed, --settings 계층 중 하나라도 permissions.defaultMode == "bypassPermissions"이면 위반. project/local 계층의 같은 값은 v2.1.257 이상에서 무시되므로 finding 대신 info로 '버전에 따라 적용될 수 있음'만 표시. permissions.disableBypassPermissionsMode == "disable"이 유효하면 실제로는 적용되지 않으므로 severity를 low로 낮춰 보고
- **공식 문서**: [settings-reference#permissions-defaultmode](https://code.claude.com/docs/en/settings-reference#permissions-defaultmode)
- **위협**: ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse
- **메모**: 키 이름과 값 확인. 문서: bypassPermissions는 .git, .claude 같은 보호 경로 쓰기 프롬프트까지 건너뛰므로 격리 환경에서만 쓰라고 경고. 초안 대비 변경: '어느 계층이든'이 아니라, auto와 bypassPermissions는 v2.1.257부터 project/local 파일에서 효력이 없음(그 이전에는 모든 파일에서 적용). CLI 플래그(--dangerously-skip-permissions)는 설정 파일로 판정할 수 없으므로 리포트의 unknown 섹션에서 안내. 확인된 공개 사고가 없어 L2로 두지만 심각도는 critical 유지

### PERM-002 · bypassPermissions 모드 잠금(disableBypassPermissionsMode) 미설정

- **판정**: 유효 설정에서 permissions.disableBypassPermissionsMode != "disable"이면 위반(high). 값이 "disable"이지만 managed 계층이 아닌 user/project/local에만 있으면 사용자가 지울 수 있으므로 low로 보고
- **공식 문서**: [settings-reference#permissions-disablebypasspermissionsmode](https://code.claude.com/docs/en/settings-reference#permissions-disablebypasspermissionsmode)
- **위협**: ASI03 Identity & Privilege Abuse
- **메모**: 허용 값은 문자열 "disable" 하나로 확인. 설정되면 --dangerously-skip-permissions 플래그를 거부하고, 서브에이전트의 permissionMode: bypassPermissions도 무시함. 문서는 managed 설정에 두는 것을 권장. managed 파일에서 이 값이 잘못되면 제한값(disable)으로 해석됨(fail closed, v2.1.282+). 형제 키 permissions.disableAutoMode도 같은 형식("disable")이며 별도 룰 후보. level: 조직 잠금 통제라 L3

### PERM-003 · 민감 경로에 대한 Read deny 규칙 누락

- **판정**: 병합된 permissions.deny에 다음 각 대상을 덮는 Read 규칙이 없으면 대상별로 위반: ~/.ssh (예: Read(~/.ssh/**)), ~/.aws (Read(~/.aws/**)), .env (Read(./.env) 또는 Read(**/.env)), .env.* (Read(./.env.*)), *.pem (Read(**/*.pem) 또는 Read(//**/*.pem)). 규칙 경로는 gitignore 문법과 계층별 기준점(// = 파일시스템 루트, ~/ = 홈, / = 설정 소스 기준, ./ 또는 접두어 없음 = 현재 디렉터리)으로 해석해 비교
- **공식 문서**: [settings-reference#exclude-sensitive-files](https://code.claude.com/docs/en/settings-reference#exclude-sensitive-files)
- **위협**: ASI01 Agent Goal Hijack, ASI02 Tool Misuse
- **메모**: Read(path) deny 문법과 경로 접두어 의미 확인(permissions 문서). 주의: user 설정의 Read(/secrets/**)는 ~/.claude/secrets/**를 가리키므로, 프로젝트 공통 규칙은 // 또는 ~/ 접두어로 써야 함. Read deny는 내장 파일 도구와 Bash의 cat/head/tail/sed/tee, 리다이렉션 대상에는 적용되지만 grep -r처럼 파일 이름을 쓰지 않는 명령에는 적용되지 않음. 그래서 sandbox.filesystem.denyRead 병행 여부를 같이 보여주는 것이 좋음. .claudeignore는 효력이 없으므로 있으면 안내. 확인된 사고 근거가 없어 L2

### PERM-004 · 모든 Bash 명령을 허용하는 광범위 allow 규칙

- **판정**: 어느 계층이든 permissions.allow에 "Bash", "Bash(*)", "Bash( *)"처럼 모든 명령과 일치하는 규칙이 있으면 위반. 계층과 파일 경로를 evidence로 기록
- **공식 문서**: [permissions](https://code.claude.com/docs/en/permissions)
- **위협**: ASI02 Tool Misuse, ASI05 Unexpected Code Execution
- **메모**: 문서: `Bash`는 모든 Bash 명령과 일치하고 `Bash(*)`는 `Bash`와 같음. allow 배열은 계층 간에 병합되므로 한 계층만 넣어도 적용됨. 도구 이름 자리의 glob("*")은 문서상 deny/ask 규칙에서만 언급되어 allow에서의 동작은 확인하지 못함(구현 시 "*"도 보수적으로 위반 처리 권장). PowerShell 도구도 같은 구조이므로 확장 후보

### PERM-005 · 네트워크 도구(curl, wget, nc 등)를 allow

- **판정**: permissions.allow에 Bash(curl ...), Bash(wget ...), Bash(nc ...), Bash(ncat ...), Bash(socat ...) 형태 규칙이 있으면 위반. 프로그램 이름은 규칙 문자열의 첫 단어로 판정
- **공식 문서**: [permissions](https://code.claude.com/docs/en/permissions)
- **위협**: ASI02 Tool Misuse, ASI01 Agent Goal Hijack
- **메모**: 문서는 curl, wget 같은 명령을 deny로 막고, 허용할 도메인은 WebFetch(domain:...) 규칙으로 주라고 권장함. 또 인자를 제한하는 Bash 패턴(예: Bash(curl http://github.com/ *))은 옵션 순서, 리다이렉트, 변수로 쉽게 우회된다고 명시. 초안 대비: 대상 도구에 ncat, socat을 추가. 같은 이유로 sandbox.network.allowedDomains 설정 여부를 함께 표시하면 좋음

### PERM-006 · 레포의 공유 설정(.claude/settings.json)이 allow 규칙을 추가함

- **판정**: project 계층(<repo>/.claude/settings.json)의 permissions.allow 또는 permissions.additionalDirectories가 비어 있지 않으면 항목별로 위반. <repo>/.claude/settings.local.json이 git에 추적되는 경우(.git 내부를 읽지 않고 판정할 수 없으면 unknown)도 같은 기준으로 표시
- **공식 문서**: [permissions#project-allow-rules-and-workspace-trust](https://code.claude.com/docs/en/permissions#project-allow-rules-and-workspace-trust)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities, ASI03 Identity & Privilege Abuse
- **메모**: 문서: 공유 project 파일의 permissions.allow, additionalDirectories, extraKnownMarketplaces, 대부분의 env 값은 폴더를 신뢰(workspace trust)한 뒤에만 적용되고, deny/ask는 즉시 적용됨. 반면 추적되지 않는 settings.local.json의 allow는 신뢰 단계 없이 적용됨. 따라서 위험은 '신뢰 승인 한 번으로 레포가 정한 권한이 생긴다'는 점. 초안 대비: additionalDirectories를 판정 대상에 추가. 공개 CVE(CVE-2025-59536)는 같은 파일의 hooks/MCP 경로이며 allow 규칙 자체에 대한 사고는 확인하지 못해 L2

### SBX-001 · Bash 샌드박스 비활성 또는 실패 시 무방비 실행

- **판정**: 유효 설정의 sandbox.enabled가 true가 아니면(기본값 false) 위반(high). sandbox.enabled == true이지만 sandbox.failIfUnavailable != true이면 '샌드박스를 시작할 수 없을 때 샌드박스 없이 실행됨'으로 medium. sandbox.allowUnsandboxedCommands != false이면 '차단된 명령을 샌드박스 밖에서 재시도 가능'으로 low. 네이티브 Windows는 샌드박스 미지원이므로 info
- **공식 문서**: [sandboxing](https://code.claude.com/docs/en/sandboxing)
- **위협**: ASI05 Unexpected Code Execution, ASI02 Tool Misuse
- **메모**: 키 sandbox.enabled(기본 false), sandbox.failIfUnavailable, sandbox.allowUnsandboxedCommands 확인. 지원 OS: macOS, Linux, WSL2. 주의: 샌드박스는 셸 명령(Bash, PowerShell, Monitor)과 그 자식 프로세스에만 적용되고, 파일 도구, MCP 서버, Hook은 샌드박스 밖에서 실행됨. 초안('샌드박스 비활성')을 세 단계 판정으로 세분화함. managed 파일에서 sandbox 블록의 값 하나가 잘못되면 필드별로 처리됨(v2.1.283+)

### HOOK-001 · 레포, 플러그인, 스킬, 서브에이전트에서 온 Hook (공급망 검토 대상)

- **판정**: 다음 위치의 Hook 정의를 모두 목록화하고 project/plugin 출처를 finding으로 표시: <repo>/.claude/settings.json과 settings.local.json의 hooks, ~/.claude/plugins 아래 활성 플러그인의 hooks/hooks.json, <repo>/.claude/skills/*/SKILL.md와 ~/.claude/skills/*/SKILL.md frontmatter의 hooks, <repo>/.claude/agents/*.md frontmatter의 hooks. 각 항목에 이벤트 이름, type(command/http/...), 명령 또는 URL(마스킹)을 기록
- **공식 문서**: [hooks](https://code.claude.com/docs/en/hooks)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution
- **사고**: [CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- **메모**: CVE-2025-59536(Check Point): 레포의 .claude/settings.json에 넣은 Hook(SessionStart 예시)이 신뢰 대화상자에서 실행된다는 경고 없이 동작해 RCE로 이어짐. 패치됨. 문서: 플러그인 Hook은 활성화되면 user/project Hook과 병합되고, 프로젝트 서브에이전트의 frontmatter Hook은 신뢰 승인 후에만 실행되며 -p 세션은 신뢰로 치지 않음. 플러그인 security 문서: command Hook은 사용자 전체 권한으로 샌드박스 밖에서 실행됨. 초안 대비: 점검 위치에 서브에이전트 frontmatter를 추가(AGT-001과 겹치는 부분은 리포트에서 묶어 표시). 사고 근거가 있어 L1

### HOOK-002 · 정책 Hook(PreToolUse/PermissionRequest)이 실패하면 그냥 통과함(fail open)

- **판정**: PreToolUse 또는 PermissionRequest 이벤트의 command/http Hook 중 onFailure != "block"인 것이 있으면 위반. async 또는 asyncRewake를 설정한 Hook은 onFailure가 적용되지 않으므로 '정책 Hook으로 부적합'으로 별도 표시
- **공식 문서**: [hooks](https://code.claude.com/docs/en/hooks)
- **위협**: ASI02 Tool Misuse, ASI08 Cascading Failures
- **메모**: 키 onFailure, 값 "continue"(기본)와 "block", 적용 대상 command와 http 타입 확인. Claude Code v2.1.295 이상 필요(그 이전 버전은 키를 무시하므로 버전 정보가 있으면 같이 표시). 기본 동작은 fail open: 시작 실패, 0/2가 아닌 종료 코드, HTTP 오류, 타임아웃, 잘못된 출력이면 동작이 그대로 진행됨. 문서는 PreToolUse에서 타임아웃 난 Hook은 도구 호출을 막지 못한다고 경고하고, 확실한 allow/deny는 Hook 대신 권한 시스템을 쓰라고 권함. 이벤트 범위는 초안과 같음

### HOOK-003 · Hook 명령에 네트워크 전송 패턴 포함

- **판정**: 모든 출처(HOOK-001 목록)의 command Hook에서 command 또는 args에 curl, wget, nc, ncat, socat, python -c ... urllib/requests, /dev/tcp/, http:// 또는 https:// URL이 있으면 위반. type == "http" Hook은 HOOK-005에서 다루므로 여기서는 제외
- **공식 문서**: [plugins/security](https://code.claude.com/docs/en/plugins/security)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI02 Tool Misuse
- **사고**: [CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- **메모**: CVE-2025-59536은 레포 Hook으로 임의 명령을 실행한 사례로, 네트워크 전송은 그 대표적인 악용 방식. 문서: command Hook은 사용자 전체 권한으로 샌드박스 밖에서 실행되므로 sandbox.network 허용 목록이 적용되지 않음. 판정은 문자열 패턴 기반이라 우회 가능(변수나 스크립트 파일 호출)하므로, 리포트에 '탐지 못 함 ≠ 안전'이라고 명시해야 함. Hook이 스크립트 파일을 실행하면 해당 파일 내용까지 검사할지는 구현 단계에서 결정. 초안 대비: 탐지 패턴에 ncat, socat, /dev/tcp를 추가하고 http 타입 Hook을 제외

### HOOK-004 · Hook이 CLAUDE_ENV_FILE에 기록 (이후 모든 Bash 명령 앞에 실행됨)

- **판정**: SessionStart, Setup, CwdChanged, FileChanged 이벤트의 command Hook 중 command/args 또는 실행하는 스크립트에 CLAUDE_ENV_FILE 참조가 있으면 위반. project/plugin 출처면 severity를 high로 올림
- **공식 문서**: [hooks](https://code.claude.com/docs/en/hooks)
- **위협**: ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning
- **메모**: 문서: CLAUDE_ENV_FILE은 SessionStart, Setup, CwdChanged, FileChanged Hook에서 사용할 수 있고, 각 Bash 명령은 이 파일 내용을 셸 코드로 먼저 실행함. 즉 PATH 조작 등으로 이후 세션 전체에 지속적으로 영향을 줄 수 있음. 초안 대비: 대상 이벤트에 CwdChanged와 FileChanged를 추가. PowerShell 경로는 일반 대입문만 읽음(v2.1.296+). 문서에 이 변수에 대한 보안 경고는 따로 없음. 확인된 사고가 없어 L2

### HOOK-005 · HTTP Hook이 있는데 전송 URL 허용 목록(allowedHttpHookUrls) 미설정

- **판정**: 어느 출처든 type == "http" Hook이 하나 이상 있고 병합된 allowedHttpHookUrls가 정의되지 않았으면 위반. 정의되어 있으면 각 HTTP Hook의 url이 패턴과 일치하는지 표시. 헤더에 환경변수를 쓰는 Hook이 있는데 httpHookAllowedEnvVars가 미설정이면 low로 함께 보고
- **공식 문서**: [settings-reference#allowedhttphookurls](https://code.claude.com/docs/en/settings-reference#allowedhttphookurls)
- **위협**: ASI02 Tool Misuse, ASI04 Agentic Supply Chain Vulnerabilities
- **메모**: 키 allowedHttpHookUrls(모든 파일, 기본 미설정이면 모든 URL 허용, 빈 배열이면 모든 HTTP Hook 차단, 계층 간 배열 병합)와 httpHookAllowedEnvVars 확인. 허용 목록은 managed 포함 모든 출처의 Hook에 적용됨. 주의: 배열이 병합되므로 project 계층이 허용 URL을 추가할 수 있음. 엄격하게 하려면 managed allowManagedHooksOnly와 같이 써야 함. 초안 대비: httpHookAllowedEnvVars 보조 판정을 추가

### HOOK-006 · managed Hook만 허용(allowManagedHooksOnly) 미설정

- **판정**: managed 계층에 allowManagedHooksOnly == true가 없으면 info. user/project/local에 있는 같은 키는 무시되므로 evidence에 '효력 없음'으로 표시
- **공식 문서**: [settings-reference#allowmanagedhooksonly](https://code.claude.com/docs/en/settings-reference#allowmanagedhooksonly)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities
- **메모**: 키 확인. 범위는 Managed only. true이면 managed Hook, Agent SDK Hook, managed enabledPlugins로 강제 활성화한 플러그인의 Hook만 실행되고 user/project/local/기타 플러그인 Hook은 차단됨. disableCommandPluginSources를 명시하지 않으면 command 소스 플러그인도 비활성화됨. 개인 PC에서는 Hook 사용을 크게 제한하므로 info 유지. level: 조직 통제라 L3

### MCP-001 · 레포의 .mcp.json이 MCP 서버를 정의함

- **판정**: <repo>/.mcp.json의 mcpServers에 항목이 있으면 서버별로 위반(medium). 추가로 project 계층(<repo>/.claude/settings.json)에 enableAllProjectMcpServers == true 또는 enabledMcpjsonServers가 있으면 '레포가 자기 서버를 자동 승인하려 함'으로 high. disabledMcpjsonServers로 거부된 서버는 제외
- **공식 문서**: [mcp#mcp-installation-scopes](https://code.claude.com/docs/en/mcp#mcp-installation-scopes)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution
- **사고**: [CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- **메모**: CVE-2025-59536(Check Point): 레포 .claude/settings.json의 enableAllProjectMcpServers/enabledMcpjsonServers로 .mcp.json 서버가 동의 없이 실행됨. 패치 후 문서 동작: 신뢰하지 않은 폴더에서는 project 파일의 두 키를 무시하고 서버를 '⏸ Pending approval'로 둠. 단 claude -p, Agent SDK, 일부 cloud 세션에서는 승인 프롬프트를 띄울 수 없어 project 서버를 묻지 않고 로드함. 초안 대비: 자동 승인 키를 high 하위 판정으로 추가. 사고 근거가 있어 L1

### MCP-002 · stdio MCP 서버를 버전 고정 없이 패키지 러너로 실행

- **판정**: 모든 MCP 정의(<repo>/.mcp.json, ~/.claude.json의 mcpServers와 프로젝트별 mcpServers, 플러그인 .mcp.json, managed-mcp.json)에서 command가 npx, bunx, pnpm dlx, yarn dlx, uvx, pipx run이고, args의 패키지 지정자에 정확한 버전이 없거나(@latest, 범위 지정, 태그 포함) uvx에 ==버전이 없으면 위반. command가 docker이고 이미지에 @sha256 다이제스트가 없으면 low
- **공식 문서**: [mcp](https://code.claude.com/docs/en/mcp)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities
- **사고**: [postmark-mcp-backdoor](https://www.theregister.com/2025/09/29/postmark_mcp_server_code_hijacked/)
- **메모**: MCP 정의의 command/args 구조는 공식 문서로 확인. 하지만 문서에 버전 고정 권고가 없고, 판정 기준(정확한 버전 = 안전)은 전문가 판단이라 verified=false. 사고 근거: postmark-mcp는 정상 버전 15개 뒤 1.0.16에서 악성 코드가 추가되어, 버전을 고정하지 않고 최신을 받는 설치가 그대로 피해를 입음. 반대로 버전 고정은 취약 버전에 묶일 위험도 있음(CVE-2025-6514 mcp-remote 0.0.5–0.1.15) → 알려진 취약 버전 점검은 별도 룰로 제안. 초안 대비: 대상 러너에 bunx, pnpm dlx, yarn dlx, pipx run, docker를 추가하고, 점검 위치에 플러그인과 managed-mcp.json을 추가

### MCP-003 · MCP 서버 env/headers에 시크릿 원문

- **판정**: 모든 MCP 정의(MCP-002와 같은 위치)의 env 값과 headers 값이 ${VAR} 또는 ${VAR:-default} 참조가 아니고 mask 모듈의 시크릿 패턴(키 접두어, 높은 엔트로피, Authorization: Bearer 뒤 리터럴)에 걸리면 위반. evidence는 반드시 마스킹
- **공식 문서**: [mcp](https://code.claude.com/docs/en/mcp)
- **위협**: ASI03 Identity & Privilege Abuse
- **메모**: 문서: .mcp.json의 command, args, env, url, headers 값에서 ${VAR}, ${VAR:-default} 확장을 지원하고, API 키 같은 민감 값을 공유 설정에서 분리하는 용도로 소개함. 원격 url/headers에서는 Claude Code 자격 증명 변수를 빈 값으로 읽음. ~/.claude.json은 OAuth 등 다른 민감 정보도 담으므로 SPEC대로 mcpServers 관련 키만 추출. 확인된 사고가 없어 L2

### PLG-001 · 플러그인 마켓플레이스 허용 목록(strictKnownMarketplaces) 미설정

- **판정**: managed 계층에 strictKnownMarketplaces와 별칭 allowedMarketplaces가 모두 없으면 위반. 빈 배열 []은 모든 마켓플레이스 차단(공식 포함)이므로 info로 표시. disableSideloadFlags != true이면 '--plugin-dir로 허용 목록 우회 가능'으로 low 보조 finding
- **공식 문서**: [settings-reference#strictknownmarketplaces](https://code.claude.com/docs/en/settings-reference#strictknownmarketplaces)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities
- **메모**: 키 확인. 범위는 Managed, 미설정이면 어떤 마켓플레이스든 추가 가능. 별칭 allowedMarketplaces는 v2.1.232+이고, 둘 다 있으면 정식 키가 우선. 허용 목록은 마켓플레이스 소스만 맞추고 마켓플레이스 안의 개별 플러그인이나 --plugin-dir은 막지 못함(disableSideloadFlags 필요). 차단 목록은 blockedMarketplaces. managed 값이 잘못되면 빈 허용 목록으로 강제됨(v2.1.277+). 초안 대비: 별칭과 disableSideloadFlags 보조 판정을 추가. level: 조직 통제라 L3

### PLG-002 · 활성 플러그인 중 실행 코드(Hook, MCP, monitor, mod, bin/)를 포함한 것

- **판정**: enabledPlugins가 true인 각 플러그인의 캐시 디렉터리(~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/)에서 hooks/hooks.json, .mcp.json, monitors 정의, mod, bin/ 디렉터리 존재 여부를 목록화. 마켓플레이스 등급(공식 이름 목록 / 커뮤니티 / 서드파티)과 autoUpdate 여부를 함께 표시
- **공식 문서**: [plugins/security](https://code.claude.com/docs/en/plugins/security)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution
- **메모**: 문서: 설치한 플러그인은 사용자 권한으로 임의 코드를 실행할 수 있음. Hook, monitor, mod, MCP/LSP 서버 프로세스는 샌드박스 밖에서 실행되고 bin/은 Bash PATH에 추가됨. auto-update가 켜져 있으면 검토한 파일이 바뀔 수 있음. 초안 대비: 목록 대상에 monitor, mod, LSP, bin/을 추가하고 마켓플레이스 등급과 autoUpdate 표시를 추가. 플러그인 서브에이전트는 hooks/mcpServers/permissionMode frontmatter를 무시함(AGT-001 참고). 플러그인 관련 공개 사고는 확인하지 못해 L2

### WF-001 · 레포에 동적 워크플로우 스크립트(.claude/workflows/*.js) 존재

- **판정**: <repo>/.claude/workflows/ 아래 *.js 파일과 ~/.claude/workflows/ 아래 파일을 목록화하고, 각 파일의 export const meta의 name/description을 정적으로 추출. 실행하거나 eval하지 않음. 같은 이름이 project와 user에 모두 있으면 project가 우선한다는 점을 표시
- **공식 문서**: [workflows#save-the-workflow-for-reuse](https://code.claude.com/docs/en/workflows#save-the-workflow-for-reuse)
- **위협**: ASI01 Agent Goal Hijack, ASI04 Agentic Supply Chain Vulnerabilities
- **메모**: 문서: 워크플로우는 서브에이전트를 조율하는 JavaScript 스크립트이고, 레포의 .claude/workflows/에 저장하면 클론한 모든 사람에게 공유되며 /<name> 명령이 됨. 이름이 겹치면 project 것이 실행됨. 스크립트 자체는 파일시스템과 셸에 직접 접근하지 못하고, 에이전트의 도구 호출은 같은 권한 검사와 샌드박스를 받음. 따라서 위험은 직접 코드 실행보다 레포가 에이전트 프롬프트를 조종하는 것(ASI01). 실행 전 승인 프롬프트는 bypassPermissions와 claude -p에서는 뜨지 않음. 조직 차단 키는 disableWorkflows. 초안 대비: 파일 확장자(*.js)와 이름 충돌 규칙을 명시. 공개 사고가 없어 L2

### AGT-001 · 서브에이전트 frontmatter에 Hook, 인라인 MCP, 권한 모드 정의

- **판정**: <repo>/.claude/agents/*.md와 ~/.claude/agents/*.md의 YAML frontmatter를 안전하게 파싱(표준 라이브러리로 제한된 키만 추출)해서 hooks가 있으면 위반. 같은 파일에 permissionMode: bypassPermissions 또는 인라인 mcpServers 정의가 있으면 함께 보고. 플러그인 서브에이전트는 이 세 필드를 무시하므로 제외
- **공식 문서**: [sub-agents#supported-frontmatter-fields](https://code.claude.com/docs/en/sub-agents#supported-frontmatter-fields)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution
- **메모**: frontmatter 필드 hooks, permissionMode, mcpServers 확인. 문서: 프로젝트 서브에이전트의 frontmatter Hook과 인라인 MCP 서버는 해당 폴더를 신뢰한 뒤에만 실행되고(-p 세션은 신뢰로 치지 않음), ~/.claude/agents/와 --agents의 Hook은 신뢰 단계 없이 실행됨. permissionMode: bypassPermissions는 메인 대화도 bypass일 때만 적용되며, disableBypassPermissionsMode가 설정되면 무시됨. 초안 대비: permissionMode와 mcpServers를 판정에 추가. 스킬 SKILL.md frontmatter에도 hooks 필드가 있으므로 HOOK-001에서 다룸

### ENV-001 · settings의 env에 시크릿 원문

- **판정**: 모든 계층의 env 객체 값 중 mask 모듈의 시크릿 패턴에 걸리는 것이 있으면 위반. 키 이름에 KEY, TOKEN, SECRET, PASSWORD, CREDENTIAL이 들어가고 값이 비어 있지 않은 경우도 위반 후보로 표시. evidence는 키 이름과 마스킹된 값만
- **공식 문서**: [settings-reference#env](https://code.claude.com/docs/en/settings-reference#env)
- **위협**: ASI03 Identity & Privilege Abuse
- **메모**: 문서: env 값은 설정 파일에 평문으로 저장되고 Claude Code가 시작하는 모든 하위 프로세스에 전달됨. API 자격 증명은 apiKeyHelper, 순환하는 OTLP 토큰은 otelHeadersHelper를 쓰라고 권장. project/local env에서 무시되는 변수 목록(CLAUDE_CODE_OAUTH_TOKEN 등)이 있으므로 무시되는 값은 '효력 없음'으로 표시하되 평문 노출 자체는 위반으로 유지. 관련 사고 CVE-2026-21852는 env의 ANTHROPIC_BASE_URL을 악용한 것으로 시크릿 원문 문제가 아니라서 incident_ref에 넣지 않음(별도 룰 제안)

### VER-001 · managed에 최소 실행 버전(requiredMinimumVersion) 미설정

- **판정**: managed 계층에 requiredMinimumVersion이 없거나 유효한 버전 문자열이 아니면 위반. minimumVersion만 있으면 '자동 업데이트 하한일 뿐 시작을 막지 않음'으로 표시. user/project의 requiredMinimumVersion은 무시되므로 '효력 없음'으로 표시
- **공식 문서**: [settings-reference#requiredminimumversion](https://code.claude.com/docs/en/settings-reference#requiredminimumversion)
- **위협**: ASI04 Agentic Supply Chain Vulnerabilities
- **사고**: [CVE-2025-59536](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/), [CVE-2026-21852](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- **메모**: 키 이름 확인: 초안의 '최소 버전 요구 설정'은 requiredMinimumVersion(Managed only, v2.1.163+, 형식 "2.1.150")임. 시작 시에만 확인하므로 이미 실행 중인 세션은 계속됨. 잘못된 값은 의도적으로 무시됨(fail open). minimumVersion(모든 파일)은 업데이트 하한일 뿐 시작을 막지 않음. 상한은 requiredMaximumVersion. 사고 근거: CVE-2025-59536과 CVE-2026-21852는 업데이트로만 해결되므로 구버전 실행을 막는 통제가 필요함. 사고 근거는 있지만 조직 통제 성격이라 level은 L3, 직접 악용 경로가 아니라서 severity low 유지

## 참조한 사고

| ID | 내용 | 출처 |
|---|---|---|
| CVE-2025-59536 | Claude Code: 레포의 .claude/settings.json Hook과 .mcp.json MCP 서버가 신뢰 확인 전에 실행됨 (enableAllProjectMcpServers / enabledMcpjsonServers 자동 승인 포함) | [Check Point Research (2026-02-25)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| CVE-2026-21852 | Claude Code: 레포 settings의 env.ANTHROPIC_BASE_URL로 신뢰 확인 전 API 요청과 인증 헤더가 공격자 서버로 전송됨 | [Check Point Research (2026-02-25)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| postmark-mcp-backdoor | npm의 postmark-mcp 1.0.16: 정상 버전 15개 뒤에 추가된 업데이트가 모든 발송 메일을 공격자에게 BCC (첫 악성 MCP 서버 사례) | [The Register (2025-09-29), 발견자 Koi Security](https://www.theregister.com/2025/09/29/postmark_mcp_server_code_hijacked/) |
| CVE-2025-6514 | mcp-remote 0.0.5–0.1.15: 악성 MCP 서버가 authorization_endpoint로 클라이언트에서 OS 명령 실행 (CVSS 9.6, 0.1.16에서 수정) | [JFrog (2025-07)](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/) |

위협 분류: [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents
