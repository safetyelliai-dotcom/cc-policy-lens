# 개인 PC에 managed 설정 설치 (macOS)

```bash
sudo mkdir -p "/Library/Application Support/ClaudeCode"
sudo cp examples/managed-settings.personal.json "/Library/Application Support/ClaudeCode/managed-settings.json"
sudo chown root:wheel "/Library/Application Support/ClaudeCode/managed-settings.json"
sudo chmod 644 "/Library/Application Support/ClaudeCode/managed-settings.json"
```

확인: Claude Code에서 `/status` → Setting sources에 managed가 보이는지, `/permissions`에서 deny 규칙 출처가 managed인지.

제거:
```bash
sudo rm "/Library/Application Support/ClaudeCode/managed-settings.json"
```

> 이 명령들은 Claude Code가 아니라 직접 터미널에서 실행한다. 프로젝트 Hook과 deny 규칙이 Claude의 sudo 실행을 막도록 설계돼 있다.
