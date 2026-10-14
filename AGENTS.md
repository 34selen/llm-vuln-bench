# AGENTS.md

LLM 취약점 탐지 교란 벤치마크. `cases/` 의 소스 코드를 pi 코딩 에이전트(GLM 5.3)로 판정시키고, 언어·변형별 탐지율·오탐율을 집계한다.
사용법·결과는 `README.md` 참고. 이 파일은 코드를 고치는 에이전트를 위한 규칙이다.

## 구조

- `benchcore/judge.py` — pi 명령 생성·실행, JSONL 도구 이벤트 파싱·인자 검증. pi 는 빈 임시 디렉터리에서 실행한다
  (케이스 폴더명·case.json 에 정답이 있으므로 도구를 켠 판정자가 읽지 못하게).
- `benchcore/submit_verdict.ts` — pi 확장. 판정 제출 도구 하나를 제공하며 제출 후 평가를 종료한다.
- `benchcore/verdict.schema.json` — 제출 도구와 Python 검증기가 공유하는 입력 스키마.
- `run_pi.py` — 케이스 × 반복마다 `benchcore.judge` 로 1회 판정 → `results/<run>/records.jsonl` 에 append.
- `aggregate.py` — `records.jsonl` → `summary.md`, `summary.csv`.
- `run_all.sh` — run → aggregate.
- `cases/<sample>__<label>__<transform>/code.*` (+ 선택 `case.json`) — 폴더명이 곧 메타데이터. `<label>` 은 `vuln` | `safe`.
  `source` 는 case.json 또는 samples.json 에 지정할 수 있으며, 없으면 폴더의 code.* 파일 한 개를 사용한다.
  `language` 는 samples.json 에서 가져오고 case.json 에서 덮어쓸 수 있다. 언어는 기록·집계에만 사용한다.
  사용자 프롬프트는 짧은 취약 여부 확인 요청과 소스 경로·코드를 전달한다.
  판정 기준과 UNCERTAIN 사용 기준은 시스템 프롬프트에, 제출 규칙은 도구와 각 인자의 설명에 둔다.
  레포에는 비워 두고(`.gitkeep` 만) 케이스를 미리 커밋하지 않는다. `results/` 의 기존 run 에 쓰인 케이스는 커밋 `d62241a` 에 있다.
- `samples.json` — sample → CWE, 제목, 언어, 대상 함수, 선택적 소스 경로.
- `prompts/system.md` (기본 판정의 UNCERTAIN 사용 기준), `prompts/system_any.md` (위험 패턴 존재?), `prompts/user.md` (`{source}`, `{code}` 템플릿).
- `config.json` — model, thinking, repeats, tools, jobs, timeout_sec, retries, pi_extra_args (선택 pi_bin).

## 규칙

- **이 레포는 변형 코드를 생성하지 않는다.** 케이스는 사람이 만들어 `cases/` 에 넣는다. 생성기 스크립트를 추가하지 말 것.
- 새 케이스는 생성 단계에서 취약/안전 판정 근거와 변형 후 취약점 보존 근거를 함께 작성하고,
  사람이 검수하여 라벨을 확정한 뒤 넣는다. 플랫폼은 입력된 라벨을 정답으로 사용하며 자동 검증하지 않는다.
- 의존성 추가 금지 (Python 표준 라이브러리만). pi 는 Node 22+ 전역 설치.
- `results/<run>/records.jsonl` 은 실행 중 append-only 실험 기록이다. 기존 run 의 기록을 수정·삭제하지 않는다.
  이미 존재하는 run-name 은 거절한다. 중단된 실험이나 새 조건은 새 `--run-name` 으로 실행한다.
  집계는 기존 기록에서 요약 파일을 다시 생성할 수 있으며, 과거 중복 기록은 (case, repeat) 별 마지막 기록을 쓴다.
- 실패 기록에도 케이스·언어·소스·실험 조건을 유지한다. 오류는 `error_type` 으로 분류하고 판정값을 비운다.
  집계에서 실패는 n/unparsed/errors 에 포함하며, 모델의 NO/UNCERTAIN 과 구분한다.
- 판정은 성공한 submit_verdict 호출 하나에서만 읽는다. 텍스트 JSON 을 판정으로 파싱하지 않는다.
  호출 누락·스키마 위반·실행 실패·중복 제출은 재시도한다. response_mode 와 제출 인자를 기록한다.
- `results/*/raw/` 와 `.env` 는 git 제외. API 키(`ZAI_API_KEY`)를 커밋하거나 출력하지 말 것.
- 실험 조건은 thinking=medium, submit_verdict 도구 하나가 기본이다. read/bash 등의 다른 도구는 허용하지 않는다.
  GLM 5.3 은 thinking off 여도 추론하므로 off 는 통제 조건이 아니다. 기존 results/ 는 JSON 텍스트 방식의 과거 실험이다.
- 새 변형 이름을 추가하면 `aggregate.py` 의 `ORDER` 에도 넣어야 표 순서가 맞는다 (없으면 알파벳순으로 뒤에 붙음).
- 결과를 README 에 반영할 때는 `results/<run>/summary.md` 의 숫자를 그대로 쓴다.

## 검증

API 호출 없이 파이프라인 점검:

```bash
python3 -m unittest discover -s tests -v
BENCH_TEST_PI="$(command -v pi)" python3 -m unittest discover -s tests -v  # Node 22+; 로컬 모의 서버, 외부 모델 API 없음
python3 run_pi.py --dry-run          # 케이스가 있을 때 실제 pi 명령만 출력; 결과 파일 생성 없음
```

실제 호출은 비용·시간이 든다 (combo 케이스 1건에 약 200초, 추론 토큰 약 2만). 전체 run 은 사용자 확인 후 실행하고,
테스트는 `--filter`, `--limit`, `--repeats 1` 로 좁힌다.

## 실험 설계상 알려진 한계

- 정답 라벨과 변형 후 취약점 보존 여부는 사전 검수에 의존한다. 라벨 오류는 실험 결과를 오염시킬 수 있다.
- safe 변형은 두 분기 모두 안전 코드라 조건 계산이 필요 없다 → `system_any.md` 의 오탐 trade-off 를 측정하지 못한다.
- disguise, sat3_170, sat3_325 에는 safe 대조군이 없다.
- 셀당 n=15 (샘플 5 × 반복 3), temperature 는 pi 기본값.
