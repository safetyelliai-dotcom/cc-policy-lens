# cc-policy-lens — 프로젝트 규칙

## 이 도구의 정체성
- Claude Code 설정을 보안 관점에서 점검하는 **읽기 전용** CLI.
- 사용자의 설정 파일을 **절대 수정하지 않는다**. 쓰기는 `--out`으로 지정한 리포트 파일 하나뿐.

## 기술 제약
- Python 3.10+, **표준 라이브러리만** 사용 (외부 패키지 추가 금지. 필요하면 먼저 물어볼 것)
- 패키지 위치: `cc_policy_lens/`, 테스트: `tests/` (표준 unittest 사용, `python3 -m unittest discover -s tests`)
- 실행: `python3 -m cc_policy_lens ...`

## 보안 규칙 (반드시 지킬 것)
1. **개발 중 실제 설정 파일을 읽지 말 것.** `~/.claude.json`, `~/.claude/`, managed 경로 대신 `tests/fixtures/`의 가짜 설정만 사용한다.
2. **테스트용 가짜 시크릿은 런타임에 조합해서 만든다.** 예: `"sk-" + "ant-" + "x" * 24`. 
   시크릿처럼 보이는 문자열을 파일에 그대로 쓰면 Hook이 차단한다 (의도된 동작).
3. 리포트, 로그, 예외 메시지에 시크릿 값을 그대로 출력하지 않는다. 항상 `mask` 모듈을 거친다.
4. 네트워크 접근 코드 금지. 이 도구는 오프라인으로만 동작한다.
5. `eval`, `exec`, `subprocess(shell=True)` 금지. 파일 권한 확인은 `os.stat`으로.

## 설정 키 정확성
- Claude Code 설정 키와 계층 규칙은 버전마다 바뀐다. 룰을 구현할 때 키 이름이 확실하지 않으면
  공식 문서(code.claude.com/docs)를 확인하고, 확인하지 못한 키는 룰 메타데이터에 `verified = false`로 표시한다.
- 룰 정의(메타데이터)와 판정 로직을 분리해, 키가 바뀌어도 쉽게 고칠 수 있게 한다.

## 작업 방식
- 각 단계는 `docs/BUILD_PLAN.md`를 따른다.
- 새 점검 룰은 `write-check-rule` 스킬 절차대로 추가한다.
- 단계가 끝나면 `security-reviewer` 서브에이전트로 검토한다.
