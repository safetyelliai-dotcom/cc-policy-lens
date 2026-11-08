# cc-policy-lens

Claude Code 설정을 **읽기 전용**으로 수집하고, 모든 계층(managed / user / project / local)을 병합한 최종 유효 설정을 **보안 관점에서 점검**하는 도구.

- 바꾸지 않는다: 설정 파일에 절대 쓰지 않음 (출력 리포트 파일만 생성)
- managed 계층 포함, 출처 추적
- 룰 기반 리스크 판정 (Critical / High / Medium / Low / Info)
- 리포트의 시크릿 자동 마스킹
- Python 3.10+ 표준 라이브러리만 사용

## 빠른 시작 (Claude Code로 빌드)

1. `claude --version` 확인 (권장 v2.1.295+, `onFailure` Hook 옵션 때문)
2. 이 폴더에서 `git init` 후 `claude` 실행 → 폴더 신뢰(trust) 승인
3. 세션 안에서 `/status`, `/permissions`, `/hooks`, `/agents`로 세팅 확인
4. `docs/BUILD_PLAN.md`의 단계별 프롬프트를 순서대로 실행

## 실행 (완성 후, 일반 터미널에서)

```bash
python3 -m cc_policy_lens scan --project /path/to/repo --format html --out report.html
```

> 실제 설정 스캔은 Claude Code 세션 안이 아니라 **일반 터미널에서** 실행한다. 
> 개발 중 Claude가 실제 토큰이 든 설정 파일을 읽지 않게 하기 위한 설계다.

## 문서

- `docs/SPEC.md` — 아키텍처, 수집 대상, 병합 규칙, 출력
- `docs/RULES.md` — 점검 룰 명세
- `docs/BUILD_PLAN.md` — Claude Code 단계별 빌드 프롬프트
- `examples/managed-settings.personal.json` — 개인 PC용 managed 설정 예시
