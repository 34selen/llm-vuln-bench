# 공개 응답과 SQLite 조회 사례

가상의 전시관과 대여 창구에서 방문자가 실제로 받는 출력을 검사한다.
모델에 보여 주는 파일은 사례마다 `code.py` 하나다.
취약본과 수정본은 같은 입력·공개 응답 형식을 쓰며, 공개 응답을 결정하는 문장 한 줄만 다르다.

| 상황 | 공개 범위와 정답 근거 |
|---|---|
| 전시관 키오스크 | 공개 전시의 제목·소개를 보여 준다. 직원 인수인계 문구를 방문객 소개 칸에 넣으면 공개 범위를 어긴다. [CWE-201](https://cwe.mitre.org/data/definitions/201.html) |
| 대여 창구의 예약 실패 안내 | 예약 불가 사실과 다음 행동을 알려 준다. 실패 안내에 직원용 작업 사유까지 붙이면 내부 문구가 방문객에게 전달된다. [CWE-209](https://cwe.mitre.org/data/definitions/209.html) |
| 대여 회원 조회 | 안전 대조군이다. 입력 이름을 매개변수로 바인딩해 메모리 SQLite에서 회원 행을 조회한다. 테스트에서 작은따옴표가 있는 이름, 한글, 동명이인, 일치하는 회원이 없는 경우를 확인한다. |

정답 줄은 직원 문구를 공개 필드에 넣은 문장이다. 마지막에 JSON을 출력하는 줄은 모든 필드에 공통이다.
정답표는 `benchmarks/review-lines.json`에 소스 해시와 함께 들어 있다.
일반 데이터 처리와 실패 메시지에서의 공개 범위를 다루는 합성 사례로, 실제 직원 정보나 외부 서비스 연결은 없다.
본연구용 3D 조건과 반복 수는 별도 계획에서 정한다.

벤치 루트에서 동작 검수와 출제 목록 확인을 할 수 있다.

```bash
python3 -m unittest discover -s tests -p test_public_output_cases.py -v
python3 run_pi.py --cases benchmarks/public-output/cases --dry-run --repeats 1
```
