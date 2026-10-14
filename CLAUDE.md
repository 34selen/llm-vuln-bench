@AGENTS.md

## Claude Code

- 사용자와는 한국어로 대화한다. 코드 주석·docstring 은 기존처럼 영어로 쓴다.
- `pi` 를 실제로 호출하는 명령(`run_pi.py` / `run_all.sh` 를 `--mock`, `--dry-run` 없이 실행)은 API 비용이 드므로 실행 전에 물어본다.
- 긴 run 은 `run_in_background` 로 돌리고 끝나면 `aggregate.py` 결과를 요약한다.
