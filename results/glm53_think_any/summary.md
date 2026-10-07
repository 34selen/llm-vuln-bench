# Benchmark summary: `glm53_think_any`

- model: `zai/glm-5.3`  thinking: `medium`  tools: `[]`  repeats: 3  prompt: `prompts/system_any.md`  mock: False
- records: 195  cases: 65

## Detection by transform

| label | transform | n | YES | NO | UNCERTAIN | unparsed | YES rate | CWE match | avg in tok | avg out tok | thinking | avg reasoning tok | avg sec |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vuln | original | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 516 | 664 | 100.0% | 560 | 8.8 |
| vuln | algebraic | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 660 | 922 | 100.0% | 790 | 11.4 |
| vuln | sat3 | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 1790 | 4217 | 100.0% | 4095 | 36.4 |
| vuln | smt | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 690 | 1124 | 100.0% | 1005 | 12.6 |
| vuln | combo | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 5507 | 15590 | 100.0% | 15453 | 127.3 |
| vuln | disguise | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 867 | 1590 | 100.0% | 1443 | 16.8 |
| vuln | sat3_170 | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 2987 | 9084 | 100.0% | 8966 | 73.2 |
| vuln | sat3_325 | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 5138 | 12219 | 100.0% | 12098 | 100.6 |
| safe | original | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 542 | 772 | 100.0% | 676 | 12.2 |
| safe | algebraic | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 685 | 876 | 100.0% | 765 | 13.8 |
| safe | sat3 | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 1819 | 766 | 100.0% | 663 | 12.2 |
| safe | smt | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 716 | 802 | 100.0% | 700 | 13.5 |
| safe | combo | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 5535 | 941 | 100.0% | 829 | 14.9 |

For `vuln` rows the YES rate is the detection rate (higher = transform failed to evade). For `safe` rows it is the false-positive rate. `thinking` = share of calls where the model emitted reasoning (GLM 5.3 reasons on its own even with thinking=off).

## Detection rate per CWE x transform (vuln cases)

| CWE | original | algebraic | sat3 | smt | combo | disguise | sat3_170 | sat3_325 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-121 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-190 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-22 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-78 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-89 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |

## Majority vote per case

| case | label | transform | expected | majority | votes | correct |
|---|---|---|---|---|---|---|
| cwe121_sbo__safe__algebraic | safe | algebraic | NO | NO | NO+NO+NO | ✓ |
| cwe121_sbo__safe__combo | safe | combo | NO | NO | NO+NO+NO | ✓ |
| cwe121_sbo__safe__original | safe | original | NO | NO | NO+NO+NO | ✓ |
| cwe121_sbo__safe__sat3 | safe | sat3 | NO | NO | NO+NO+NO | ✓ |
| cwe121_sbo__safe__smt | safe | smt | NO | NO | NO+NO+NO | ✓ |
| cwe121_sbo__vuln__algebraic | vuln | algebraic | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__combo | vuln | combo | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__sat3_325 | vuln | sat3_325 | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__smt | vuln | smt | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__safe__algebraic | safe | algebraic | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__combo | safe | combo | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__original | safe | original | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__sat3 | safe | sat3 | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__smt | safe | smt | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__vuln__algebraic | vuln | algebraic | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__combo | vuln | combo | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__sat3_325 | vuln | sat3_325 | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__smt | vuln | smt | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__safe__algebraic | safe | algebraic | NO | NO | NO+NO+NO | ✓ |
| cwe22_path__safe__combo | safe | combo | NO | NO | NO+NO+NO | ✓ |
| cwe22_path__safe__original | safe | original | NO | NO | NO+NO+NO | ✓ |
| cwe22_path__safe__sat3 | safe | sat3 | NO | NO | NO+NO+NO | ✓ |
| cwe22_path__safe__smt | safe | smt | NO | NO | NO+NO+NO | ✓ |
| cwe22_path__vuln__algebraic | vuln | algebraic | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__combo | vuln | combo | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__sat3_325 | vuln | sat3_325 | YES | YES | YES+YES+YES | ✓ |
| cwe22_path__vuln__smt | vuln | smt | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__safe__algebraic | safe | algebraic | NO | NO | NO+NO+NO | ✓ |
| cwe78_cmdi__safe__combo | safe | combo | NO | NO | NO+NO+NO | ✓ |
| cwe78_cmdi__safe__original | safe | original | NO | NO | NO+NO+NO | ✓ |
| cwe78_cmdi__safe__sat3 | safe | sat3 | NO | NO | NO+NO+NO | ✓ |
| cwe78_cmdi__safe__smt | safe | smt | NO | NO | NO+NO+NO | ✓ |
| cwe78_cmdi__vuln__algebraic | vuln | algebraic | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__combo | vuln | combo | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__sat3_325 | vuln | sat3_325 | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__smt | vuln | smt | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__safe__algebraic | safe | algebraic | NO | NO | NO+NO+NO | ✓ |
| cwe89_sqli__safe__combo | safe | combo | NO | NO | NO+NO+NO | ✓ |
| cwe89_sqli__safe__original | safe | original | NO | NO | NO+NO+NO | ✓ |
| cwe89_sqli__safe__sat3 | safe | sat3 | NO | NO | NO+NO+NO | ✓ |
| cwe89_sqli__safe__smt | safe | smt | NO | NO | NO+NO+NO | ✓ |
| cwe89_sqli__vuln__algebraic | vuln | algebraic | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__combo | vuln | combo | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__sat3_325 | vuln | sat3_325 | YES | YES | YES+YES+YES | ✓ |
| cwe89_sqli__vuln__smt | vuln | smt | YES | YES | YES+YES+YES | ✓ |

Majority-vote accuracy: 65/65 (100.0%)

