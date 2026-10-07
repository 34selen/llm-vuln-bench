# LLM 취약점 탐지 교란 벤치마크 (pi + GLM 5.3)

`cases/` 에 들어 있는 C 코드를 pi 코딩 에이전트(GLM 5.3)에게 보여 주고 취약 여부를 판별시킨 뒤,
변형 조건별 탐지율·오탐율·보류율을 집계한다. 4주차 보고서의 검증 실험 1·2를 반복 가능하게 만든 것이다.

변형 코드는 이 레포에서 만들지 않는다. 사람이 (Claude Code 등으로) 만들어 `cases/` 에 넣으면 레포는 평가와 집계만 한다.

```
samples.json     샘플 이름 → CWE, 제목, 대상 함수 조회표
cases/<sample>__<label>__<name>/code.c       평가할 코드 (사람이 넣음) + 선택적 case.json
run_pi.py        pi로 GLM 호출 → results/<run>/records.jsonl
aggregate.py     조건별 탐지율 / CWE 일치율 / 보류율 / 다수결 → summary.md, summary.csv
run_all.sh       run → aggregate
config.json      모델, thinking, 반복 횟수, 병렬 수
prompts/         system.md (판정자 역할, JSON 출력 강제), user.md (코드 템플릿)
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
./run_all.sh glm53_notools
# 단계별
python3 run_pi.py --run-name glm53_notools
python3 aggregate.py glm53_notools
```

옵션:

```bash
python3 run_pi.py --mock                        # API 없이 파이프라인 점검
python3 run_pi.py --dry-run                     # 실제 pi 명령만 출력
python3 run_pi.py --filter __sat3 --limit 2     # 일부만
python3 run_pi.py --thinking medium --run-name glm53_think   # thinking 켜고 비교
python3 run_pi.py --tools read,bash --run-name glm53_tools   # 도구 허용 (기본은 --no-tools, 1턴 호출)
python3 run_pi.py --model zai-api/glm-5.3 ...   # 엔드포인트 변경
```

같은 run-name 으로 다시 실행하면 이미 평가된 (케이스, 반복)은 건너뛴다.
단 `code.c` 내용이 바뀐 케이스는 다시 평가한다 (코드 해시로 판단). 집계는 (케이스, 반복)별 최신 기록만 쓴다.

## 케이스 추가하기

1. `cases/<sample>__<label>__<name>/` 폴더를 만든다.
   - `<sample>`: `samples.json` 에 있는 이름 (cwe89_sqli, cwe78_cmdi, cwe121_sbo, cwe22_path, cwe190_intov)
   - `<label>`: `vuln` 또는 `safe` (정답 라벨)
   - `<name>`: 변형 이름. 집계표의 행이 된다 (original, sat3, mytrick ...)
2. 그 안에 `code.c` 를 넣는다.
3. `python3 run_pi.py --run-name <run> --filter __<name>` 으로 그 변형만 평가하고 `aggregate.py` 로 집계한다.

`case.json` 은 선택 사항이다. 폴더명에서 sample/label/transform 을 읽고, CWE·함수명은 `samples.json` 에서 가져온다.

현재 들어 있는 50개 케이스는 2026-10-07에 생성한 것으로, 변형 5종(original, algebraic, sat3, smt, combo) × 샘플 5개 × {vuln, safe} 이다.
모두 대상 함수 본문을 `if (항상참) { 원본 } else { safe.c 본문 }` 으로 감싼 형태다.

## 샘플 추가하기

`samples.json` 에 항목을 추가하고, 원본 코드는 `cases/<이름>__vuln__original/code.c` (와 `__safe__original`) 로 넣는다.

```json
"cwe89_sqli": { "cwe": "CWE-89", "title": "SQL Injection", "language": "c", "function": "lookup_user" }
```

## 결과 해석

- `vuln` 행의 YES rate = 탐지율. 낮을수록 변형이 교란에 성공.
- `safe` 행의 YES rate = 오탐율.
- UNCERTAIN = 보고서의 "판단 보류". YES/NO 와 별도로 집계.
- CWE match = YES 이면서 CWE 번호까지 맞춘 비율.
- `results/<run>/raw/` 에 pi 의 JSONL 원문(usage, 비용 포함)이 남는다.

## 주의

- pi 1.0.4 기준. 기본은 `--no-tools` + thinking off 라 케이스당 1턴 호출이다.
  도구를 켜면 모델이 코드를 컴파일·실행하거나 조건식을 직접 풀 수 있어 실험 조건이 달라진다.
- temperature 는 pi 기본값. 결과 변동은 반복 횟수(`repeats`)로 흡수한다.
- 변형본이 원본의 취약점을 실제로 유지하는지는 이 레포가 검사하지 않는다. 케이스를 넣는 사람이 책임진다.
