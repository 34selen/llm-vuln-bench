# LLM 취약점 탐지 교란 벤치마크 (pi + GLM 5.3)

`cases/` 에 들어 있는 소스 코드를 pi 코딩 에이전트(GLM 5.3)에게 보여 주고 취약 여부를 판별시킨 뒤,
변형 조건별 탐지율·오탐율·보류율을 집계한다. 4주차 보고서의 검증 실험 1·2를 반복 가능하게 만든 것이다.

변형 코드는 이 레포에서 만들지 않는다. 사람이 (Claude Code 등으로) 만들어 `cases/` 에 넣으면 레포는 평가와 집계만 한다.
케이스의 취약/안전 라벨과 변형 후 취약점 보존 여부는 사전 검수로 확정하며, 플랫폼은 입력된 라벨을 정답으로 사용한다.

```
samples.json     샘플 이름 → CWE, 제목, 언어, 대상 함수
cases/<sample>__<label>__<name>/code.*      평가할 코드 (사람이 넣음) + 선택적 case.json
benchcore/       judge.py (pi 호출·도구 이벤트 파싱), submit_verdict.ts (판정 제출 도구), verdict.schema.json (입력 스키마)
run_pi.py        pi로 GLM 호출 → results/<run>/records.jsonl
aggregate.py     언어·조건별 탐지율 / CWE 일치율 / 보류율 / 오류 / 다수결 → summary.md, summary.csv
run_all.sh       run → aggregate
config.json      모델, thinking, 반복 횟수, 병렬 수
prompts/         system.md (기본 판정의 UNCERTAIN 사용 기준), system_any.md (도달 여부 무시, 위험 패턴 존재만 묻는 프롬프트), user.md (코드 템플릿)
.env             ZAI_API_KEY (git 제외)
models.json      종량제 엔드포인트 zai-api/glm-5.3 등록 (~/.pi/agent/models.json 에 복사됨)
```

## 설치

```bash
nvm install 22 && nvm use 22                      # pi 는 Node 22 이상 필요 (기본값 22 로 설정됨)
npm install -g @earendil-works/pi-coding-agent    # 또는 curl -fsSL https://pi.dev/install.sh | sh
cp .env.example .env && $EDITOR .env              # ZAI_API_KEY=... (run_pi.py 가 자동으로 읽음)
pi --list-models glm-5.3                          # zai/glm-5.3 이 보여야 함
```

`zai/glm-5.3` 은 GLM Coding Plan 엔드포인트, `zai-api/glm-5.3` 은 종량제 API 엔드포인트다.
키 종류에 맞게 `config.json` 의 `model` 을 고른다. 키가 맞지 않으면 `401 token expired or incorrect` 로 기록된다.

## 실행

```bash
./run_all.sh glm53_tool_001
# 단계별
python3 run_pi.py --run-name glm53_tool_001
python3 aggregate.py glm53_tool_001
```

옵션:

```bash
python3 run_pi.py --mock                        # API 없이 파이프라인 점검
python3 run_pi.py --dry-run                     # 실제 pi 명령만 출력 (결과 폴더 생성 없음)
python3 run_pi.py --filter __sat3 --limit 2     # 일부만
python3 run_pi.py --model zai-api/glm-5.3 ...   # 엔드포인트 변경
python3 run_pi.py --prompt prompts/system_any.md --run-name glm53_think_any   # 판정 프롬프트 교체
python3 run_pi.py --run-name glm53_tool_001 --resume                          # 중단된 run 이어서
```

run-name 은 한 번만 사용할 수 있다. 같은 이름의 파일이나 폴더가 이미 있으면 실행을 거절하며,
기존 설정·기록·원문을 덮어쓰거나 이어 쓰지 않는다.

**중단된 run 은 `--resume` 으로 이어서 돌린다.** `records.jsonl` 에 이미 있는 (case, repeat) 는
건너뛰고 남은 것만 평가한다. 이어 돌리지 않고 새 run-name 으로 처음부터 가면 **끝난 평가의 비용을 다시 낸다.**

- **오류로 끝난 평가도 "완료"로 센다.** 다시 돌리면 중단되지 않은 run 이 받지 못한 재시도를 그 셀에만 주는 셈이라
  조건이 달라진다. 이어 돌리기는 run 을 잇는 것이지 개선하는 것이 아니다. 그 평가를 다시 하려면 새 run-name 을 쓴다.
- **측정을 결정하는 설정이 바뀌었으면 거절한다** (model, thinking, tools, repeats, 시스템 프롬프트, mock).
  어느 칸이 어떻게 다른지 찍고 멈춘다. `jobs`·`retries`·`timeout_sec` 은 비교하지 않는다 —
  호출을 어떻게 던지냐를 바꿀 뿐 무엇을 묻는지는 바꾸지 않는다.
- `--limit` 을 같이 주면 **남은 것 중 N개**만 더 돌린다.
- 이어 돌린 시각은 `run_config.json` 의 `resumed` 에 쌓인다. 기록에 공백이 보여야 한다.
이름을 생략하면 모델 이름과 마이크로초까지 포함한 시각으로 자동 생성한다.
`aggregate.py` 는 기존 기록에서 요약 파일을 다시 생성할 수 있다.

## 케이스 추가하기

공개 응답의 직원용 문구 포함 여부를 확인하는 취약·수정본 두 쌍과 실제 SQLite 조회 안전 대조군은 [공개 출력 사례](benchmarks/public-output/README.md)에 있다.
해당 다섯 파일은 `--cases benchmarks/public-output/cases`로 선택한다.

1. `cases/<sample>__<label>__<name>/` 폴더를 만든다.
   - `<sample>`: `samples.json` 에 있는 이름 (cwe89_sqli, cwe78_cmdi, cwe121_sbo, cwe22_path, cwe190_intov)
   - `<label>`: `vuln` 또는 `safe` (정답 라벨)
   - `<name>`: 변형 이름. 집계표의 행이 된다 (original, sat3, mytrick ...)
2. 취약/안전 판정 근거와 변형 후 취약점 보존 여부를 사람이 검수하여 라벨을 확정하고, 그 안에 소스 파일을 넣는다.
3. `python3 run_pi.py --run-name <run> --filter __<name>` 으로 그 변형만 평가하고 `aggregate.py` 로 집계한다.

`case.json` 은 선택 사항이다. 폴더명에서 sample/label/transform 을 읽고, CWE·함수명·언어는 `samples.json` 에서 가져온다.
소스 경로는 `case.json` 의 `source`, `samples.json` 의 `source` 순으로 선택하며,
둘 다 없으면 폴더 안의 `code.*` 파일 한 개를 사용한다 (`code.c`, `code.cpp`, `code.py`, `code.sol` 등).
`source` 는 케이스 폴더 안의 파일을 가리키는 상대 경로다. 여러 `code.*` 파일이 있으면 명시해야 한다.

예를 들어 Python 코드를 `src/main.py` 에 넣었다면 `case.json` 을 다음과 같이 작성한다.

```json
{ "language": "python", "source": "src/main.py" }
```

사용자 프롬프트에는 짧은 취약 여부 확인 요청과 소스 경로·코드를 전달한다.
시스템 프롬프트에는 판정 기준과 UNCERTAIN 사용 기준을 두고, 제출 규칙은 도구와 각 인자의 설명에 둔다.
언어는 결과 기록과 언어별 집계에 사용하며 프롬프트에 별도로 표기하지 않는다. 한 케이스는 소스 파일 하나를 평가한다.

## 판정 제출

모델은 `submit_verdict` 도구를 한 번 호출해 판정을 제출한다. 이 도구는 입력을 기록하고 해당 평가를 종료하며,
파일 읽기나 코드 실행 기능은 없다. pi 는 발견된 확장을 비활성화하고 레포의 제출 도구만 명시적으로 로드한다.
활성 도구는 `submit_verdict` 하나로 제한한다 (`--tools read,bash` 같은 다른 도구 설정은 거절한다).

공통 입력 스키마는 `benchcore/verdict.schema.json` 에 있다. `vulnerable`, `confidence`, `reason` 은 필수이고 `cwe`, `function`, `line` 은 해당 없으면 생략한다 (기록에는 null). 알 수 없는 필드는 거절한다.

| 필드 | 조건 |
|---|---|
| vulnerable | YES / NO / UNCERTAIN |
| cwe | CWE-번호, 해당 없으면 생략 |
| function | 비어 있지 않은 함수 이름, 해당 없으면 생략 |
| line | 1 이상의 정수, 해당 없으면 생략 |
| confidence | 0~100 정수 |
| reason | 비어 있지 않은 판단 근거 |

Python 은 성공한 도구 실행의 호출 ID와 인자·결과를 대조하고 스키마를 다시 검증한다.
텍스트 응답은 로그에만 보관한다. 인자가 잘못되면 도구가 어느 필드가 왜 틀렸는지 돌려주고, 모델은 같은 세션에서 다시 제출한다
(최대 3회, 횟수는 `invalid_tool_calls` 로 기록). 그래도 실패하거나 호출 누락·미완료·중복 호출이면 재시도하며,
기본 `retries=2` 는 최초 호출 이후 최대 2회 추가 호출한다는 뜻이다. 모두 실패하면 판정값 없이 오류로 기록한다.
`records.jsonl` 에는 `response_mode: "tool"`, 제출 인자(`tool_arguments`), `pred_parse: "tool"` 이 남는다.

`cases/` 는 비어 있다. 평가할 케이스는 실험할 때마다 넣는다.
아래 "결과" 절의 65개 케이스(변형 8종 × 샘플 5개)는 커밋 `d62241a` 의 `cases/` 에 있다
(`git checkout d62241a -- cases` 로 되살린다).

## 샘플 추가하기

`samples.json` 에 항목을 추가하고, 원본 코드는 `cases/<이름>__vuln__original/code.*` (와 `__safe__original`) 로 넣는다.
`language` 는 실제 소스 언어로 지정한다. 케이스별로 `case.json` 에서 덮어쓸 수 있다.

```json
"cwe89_sqli": { "cwe": "CWE-89", "title": "SQL Injection", "language": "c", "function": "lookup_user" }
```

## 결과

아래는 제출 도구 도입 이전의 JSON 텍스트 응답 방식으로 수행한 C 실험이다.
현재 도구 방식의 실험과는 응답 조건이 다르며, 새 실험은 별도의 run-name 으로 수행한다.

GLM 5.3, thinking medium, 도구 없음, 케이스당 3회. 숫자는 **15회 중 회피(미탐지) 횟수**.

| 변형 | 내용 | `system.md` (도달 가능한 취약점?) | `system_any.md` (위험 패턴 존재?) |
|---|---|---:|---:|
| original | 원본 | 0 | 0 |
| algebraic | 대수 항등식 조건 | 0 | 0 |
| smt | 정수 항등식 조건 | 0 | 0 |
| disguise | 변수명 위장 + 허위 주석 + 더미 함수 | 0 | 0 |
| sat3 | 3-SAT 20변수·85절 | 2 | 0 |
| sat3_170 | 3-SAT 40변수·170절 | 1 | 0 |
| sat3_325 | 3-SAT 75변수·325절 | 3 | 0 |
| combo | sat3_325 + smt + disguise | **8** | 0 |

안전 코드 오탐은 두 프롬프트 모두 0/15. 전체 표는 `results/glm53_think/summary.md`, `results/glm53_think_any/summary.md`.

관찰:
- 위장만으로는 회피 0. 3-SAT 만으로는 1~3회. 둘을 합친 combo 에서 8회로 급증한다. 위장은 단독으로는 효과가 없지만
  모델이 조건식 계산을 틀렸을 때 "역시 안전한 분기였다"는 결론을 굳히는 역할을 한다.
- 회피는 전부 같은 메커니즘이다: 모델이 325절 3-SAT 상수를 직접 계산하다 리터럴 하나의 부정을 놓쳐
  (예: `(!sv41 || sv2 || !sv4)` 를 `(!sv41 || sv2 || sv4)` 로 읽음) 조건이 거짓이라 결론 내리고,
  안전한 else 분기만 실행된다고 판단한다. 확신도 80~99, UNCERTAIN 없음.
- 판정 프롬프트에서 "도달 가능한"을 빼고 "위험한 패턴이 있으면 보고"로 바꾸면 회피가 전부 사라진다 (reasoning 토큰도 20~35% 감소).
  즉 이 공격은 코드를 숨기는 것이 아니라, 모델이 도달 가능성 판단을 하도록 유도한 뒤 그 판단을 틀리게 만드는 것이다.
  반대로 그 프롬프트는 실제 dead code 도 전부 취약으로 보고하게 되므로, 실무 탐지기에서는 오탐과의 trade-off 가 된다.

## 결과 해석

- `vuln` 행의 YES rate = 탐지율. 낮을수록 변형이 교란에 성공.
- `safe` 행의 YES rate = 오탐율.
- UNCERTAIN = 보고서의 "판단 보류". YES/NO 와 별도로 집계.
- 호출 예외, timeout, 비정상 종료, 판정 파싱 실패는 `error` 와 `error_type` 으로 기록한다.
  판정은 성공한 `submit_verdict` 호출의 인자에서 읽는다. 일반 텍스트나 JSON 텍스트만 반환하면 제출 누락으로 재시도한다.
  실패도 표본 수 `n`, `unparsed`, `errors` 에 포함되며 YES/NO/UNCERTAIN 으로 집계하지 않는다.
  YES rate 의 분모는 전체 평가 수이므로, 탐지율 하락을 교란 효과로 해석하기 전에 오류 수를 확인한다.
- 집계는 언어별로 나눈다. 언어 정보가 없는 기존 C 실험 기록은 샘플의 언어를 사용한다.
- CWE match = YES 이면서 CWE 번호까지 맞춘 비율.

### 탐지한 사례의 CWE와 줄 번호 채점

`python3 aggregate.py <run>`은 기존 미탐·오탐 표와 함께 `summary.md`에 진단 정확도 표를 쓴다.
실제 취약한 사례에서 YES를 받은 뒤 CWE를 맞힌 건수, 줄을 맞힌 건수, 둘 다 맞힌 건수를 각각 센다.
예를 들어 10건 중 6건에 YES, 그중 5건에 올바른 CWE를 냈다면 전체 기준은 5/10이고 YES 기준은 5/6이다.
줄 번호는 해당 소스 버전에 정답이 있는 YES만 분모에 넣는다.
정답이 있는 문제에서 모델이 필드를 생략하면 그 항목의 분모에 남는다. 분모가 0이면 표에는 ‘—’, CSV의 비율 칸에는 빈값을 쓴다.
NO는 별도 미탐 표에, 보류와 오류는 각각의 건수에 남는다.

`summary.csv`의 `cwe_`·`line_`·`both_` 열은 적격 분모와 일치 건수를 담는다.
`review_details.csv`는 케이스·반복별로 원래 판정과 예측 줄, CWE 및 위치의 채점 상태를 보존한다.
`match`는 일치, `mismatch`는 불일치, `omitted`는 모델의 생략, `no_reference`는 정답 부재나 버전 불일치다.
`not_detected`는 실제 취약 사례에서 유효한 YES를 받지 못한 경우이며, 원래 판정 열로 NO·보류·오류를 구분한다.

정답표는 `benchmarks/review-lines.json`이다. 새 데이터나 수정한 정답표는 `python3 aggregate.py <run> --line-labels <파일>`로 지정한다.
정답표는 응시 모델에 전달하지 않는다. 입력은 다음 필드를 가진 JSON 객체의 배열이다.

| 필드 | 값 |
|---|---|
| `case_id` | 해당 케이스 ID |
| `code_sha` | 소스 원본 바이트 SHA-1의 처음 12자리. 과거 실행이 기록한 식별자 |
| `sha256` | 같은 원본 바이트의 전체 SHA-256. 새 실행은 두 해시 모두 대조 |
| `lines` | 그 버전에서 정답으로 인정하는 실제 소스 줄 번호의 배열. 첫 줄은 1 |
| `cwe` | 선택 사항. 과거 판정에 기준 CWE가 없을 때 사용할 해당 버전의 검수된 CWE |

새 문제는 모델 답안을 보기 전에 코드에서 대상 문장을 정한다. 아래 명령은 실제 파일의 줄 범위를 검사하고 두 해시를 계산해 바로 쓸 수 있는 정답표를 출력한다.

```bash
python3 -m benchcore.review_quality --case-id example__vuln__original --source path/to/source.c --lines 32 > my-lines.json
python3 aggregate.py <run> --line-labels my-lines.json
```

여러 케이스를 함께 채점할 때는 각 항목을 같은 JSON 배열에 담는다.
진단 정확도는 실행에 저장된 CWE를 사용하고, 이 값이 없으면 해당 소스 버전 정답표의 CWE를 사용한다.
개별 CSV의 `scored_cwe`가 실제 채점에 사용한 값이다. 기존 `cwe_match_rate` 열은 과거의 샘플 메타데이터 보완 방식을 유지한다.
같은 ID라도 코드가 바뀌면 새 버전으로 추가한다. SHA-256이 없던 기록은 케이스 ID와 보관된 짧은 해시가 모두 일치할 때만 채점한다.
기본 정답표의 다섯 샘플은 버퍼에 쓰는 문장, 오버플로가 일어나는 산술식, 파일을 여는 문장, 명령 실행 문장, SQL 실행 문장을 각각 기준으로 삼았다.
방어 검사가 있는 분기의 같은 문장과 취약한 연산으로 이어지는 앞뒤의 보조 문장은 이 기준에서 제외한다.
- `results/<run>/raw/` 에 pi 의 JSONL 원문(usage, 비용 포함)이 남는다. 재시도 원문은 `.attempt2.jsonl` 등의 별도 파일로 보관한다.

요약의 `Review outcomes by ground truth` 표는 취약 라벨의 안전 판정(FN), 안전 라벨의 취약 판정(FP), 보류, 실행 오류를 따로 표시한다.
`Incorrect / decisive`의 분모는 YES나 NO가 나온 건수이고, `Incorrect / requests`의 분모는 전체 요청 수다.

## 논리 문제 난이도 벤치마크

`logic_benchmark.py`는 고정된 불리언 논리 문제의 정답을 기준 솔버로 확인한다.
출력에는 절 수, 변수 수, 블록 수, 절 밀도, 솔버의 탐색 노드 수와 단위 절로 값을 정한 횟수가 들어간다.
두 작업량 수치는 동일한 기준 솔버에서 문제끼리 비교할 때 사용한다.
기준 솔버는 주어진 절 순서에서 각 블록을 독립적으로 풀고, 블록별 작업량을 합산한다.

```bash
python3 logic_benchmark.py
```

기본 문제는 `benchmarks/logic.json`에 있으며, `--suite`로 같은 형식의 논리 문제 파일을 읽을 수 있다.
`choice-sat`과 `choice-sat-with-unit`은 변수와 블록은 같고 단위 절 하나가 다른 비교용 문제다.
각 문제는 `case_id`, `expected`(SAT 또는 UNSAT), `blocks`를 가진다.
절의 양수와 음수는 각각 해당 변수가 참과 거짓일 때 만족하는 항목이다.
블록 사이는 변수를 공유하지 않으며, 기준 솔버의 작업량을 제한하기 위해 블록당 변수는 최대 16개다.
모든 단계는 표준 라이브러리만 사용하며 로컬 파일을 입력으로 받는다.

### 논리 문제 출제와 채점

평가용 `benchmarks/logic-evaluation.json`에는 서로 다른 논리식 12개가 있다.
변수·절·블록 수의 조합 6개에 각각 SAT(모든 조건을 만족하는 값이 있음)와 UNSAT(그런 값이 없음) 문제가 하나씩 있다.
예를 들어 변수 3개·절 4개·블록 1개인 두 문제는 세 숫자가 같고 정답이 서로 다르다.
SAT로만 답해도 이 세트에서는 6/12를 맞힌다.
짝마다 문제 수가 적으므로 각 조합의 결과는 해당 두 문제에 한해 해석한다.

```bash
python3 logic_calibration.py --suite benchmarks/logic-evaluation.json --verify-only
python3 logic_benchmark.py --suite benchmarks/logic-evaluation.json --form-seed 27 --questions > questions.json
python3 logic_benchmark.py --suite benchmarks/logic-evaluation.json --form-seed 27 --predictions answers.json
```

응시자에게는 `questions.json`만 전달한다. 응시자는 각 문제의 `case_id`를 키로, `SAT`, `UNSAT`, `UNCERTAIN` 중 하나를 값으로 적은 JSON 객체를 제출한다.
출제본의 식별자와 순서는 논리식 목록과 `--form-seed`로 정해진다. 출제·채점에 같은 파일과 같은 값을 쓴다(기본값 0).
기존에 내부 문제 이름으로 저장한 답안도 채점할 수 있다. 중복 답안이나 다른 출제본의 공개 ID를 쓰면 오류로 처리한다.
문제와 정답 원본은 공개되어 있으므로, 문제를 처음 접한 응시자를 평가할 때는 원본과 이전 채점 결과에 접근할 수 없는 환경을 사용한다.

채점 결과의 `score`에는 정답·오답·보류·누락 건수가 들어간다.
`metrics.accuracy_all`은 전체 문제 중 정답 비율, `accuracy_decisive`는 SAT 또는 UNSAT로 답한 문제 중 정답 비율, `coverage_decisive`는 전체 중 SAT 또는 UNSAT로 답한 비율이다.
각 비율에는 분자와 분모가 함께 들어가며 분모가 0이면 `rate`는 `null`이다.
`constant_baselines`는 한 가지로만 답했을 때의 정답률, `by_answer`는 실제 정답별 건수, `by_size`는 변수·절·블록 조합별 건수다.

### 난이도 보정 결과

`logic_calibration.py`는 블록을 합친 전체 식의 진리표로 DPLL 정답을 독립 검증하고, `benchmarks/logic-calibration.json`에 선언한 대조쌍을 비교한다.
각 쌍에서 SAT·UNSAT 정답을 동일하게 두고, 실제로 달라진 절·변수·블록 수가 비교표의 선언과 일치하는지 검증한다.
전체 변수가 16개 이하면 전체 식을 하나의 진리표로 검증한다.
더 크면 변수를 공유하지 않는 각 블록을 진리표로 검증한다. 모든 블록을 만족시킬 수 있어야 전체 정답이 SAT다.
비교 계획 없이 정답만 확인할 때는 `--verify-only`를 쓴다.

```bash
python3 logic_calibration.py
python3 logic_calibration.py --format json
```

탐색 노드와 단위 절 할당은 기준 솔버의 작업량이다.
탐색 노드에는 블록별 시작 노드가 포함되므로, 블록 수 비교에서는 작업 분할이 집계에도 영향을 준다.

## 파이프라인 검증

```bash
python3 -m unittest discover -s tests -v
```

테스트는 임시 디렉터리와 모의 응답을 사용하며 API 호출이나 기존 실험 기록 수정 없이 실행된다.
pi 가 설치된 환경에서는 로컬 모의 서버로 실제 확장 로딩·스키마 검증·종료·재시도를 확인할 수 있다.
이 통합 테스트는 외부 모델 API 를 호출하지 않는다.

```bash
nvm use 22
BENCH_TEST_PI="$(command -v pi)" python3 -m unittest discover -s tests -v
```

## 주의

- pi 1.0.4 기준. 기본은 판정 제출 도구 하나 + thinking medium 이다. 정상 제출 후 추가 모델 호출 없이 종료한다.
  GLM 5.3 은 thinking off 를 보내도 스스로 추론하므로 off 는 통제된 조건이 아니다. 평가는 thinking 을 켠 상태로만 한다.
  제출 도구는 모델의 판단을 기록하며, 코드의 실제 취약성이나 정답 라벨을 검증하지 않는다.
- temperature 는 pi 기본값. 결과 변동은 반복 횟수(`repeats`)로 흡수한다.
- 정답 라벨과 변형본의 취약점 보존 여부는 자동 검증하지 않는다. 케이스를 넣기 전에 사람이 검수해야 한다.
