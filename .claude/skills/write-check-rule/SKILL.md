---
name: write-check-rule
description: cc-policy-lens에 새 보안 점검 룰을 추가하거나 기존 룰을 고칠 때 사용. 룰 메타데이터, 판정 로직, 테스트를 한 세트로 만든다.
---
# 점검 룰 추가 절차

## 1. 명세 확인
`docs/RULES.md`에서 해당 룰의 ID, 심각도, 판정 조건을 확인한다. 명세에 없는 룰이면 먼저 명세에 추가하고 사용자 확인을 받는다.

## 2. 메타데이터 정의
`cc_policy_lens/rules/` 아래에 룰 하나당 다음 필드를 가진다:
- `id`: 예 `PERM-001`
- `title`: 한 줄 요약
- `severity`: critical / high / medium / low / info
- `rationale`: 왜 위험한가
- `remediation`: 어떻게 고치는가
- `verified`: 설정 키를 공식 문서로 확인했으면 true

## 3. 판정 로직
- 입력: 병합된 유효 설정(`EffectiveConfig`)과 계층별 원본, 출처 정보
- 출력: `Finding` 리스트 (rule_id, severity, message, evidence, source_layer, source_path)
- `evidence`에 설정값을 넣을 때는 반드시 `mask`를 거친다
- 판정 불가(파일 없음, 읽기 권한 없음)는 finding이 아니라 `unknown` 상태로 구분한다

## 4. 테스트
각 룰마다 최소 3개:
- 위반 케이스 → finding 발생
- 정상 케이스 → finding 없음
- 경계 케이스 → 해당 키 누락, 타입 이상, 다른 계층에서 덮어쓴 경우

fixture는 `tests/fixtures/<rule-id>/` 아래 계층별 JSON으로 만든다. 가짜 시크릿은 런타임 조합으로 만든다.

## 5. 완료 조건
- 테스트 통과
- `docs/RULES.md`의 상태 열 갱신
