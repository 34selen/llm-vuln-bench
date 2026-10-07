# Benchmark summary: `glm53_think`

- model: `zai/glm-5.3`  thinking: `medium`  tools: `[]`  repeats: 3  mock: False
- records: 195  cases: 65

## Detection by transform

| label | transform | n | YES | NO | UNCERTAIN | unparsed | YES rate | CWE match | avg in tok | avg out tok | thinking | avg reasoning tok | avg sec |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vuln | original | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 446 | 824 | 100.0% | 709 | 11.3 |
| vuln | algebraic | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 590 | 1083 | 100.0% | 930 | 13.6 |
| vuln | sat3 | 15 | 13 | 2 | 0 | 0 |  86.7% |  86.7% | 1720 | 6323 | 100.0% | 6195 | 60.7 |
| vuln | smt | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 620 | 1509 | 100.0% | 1363 | 18.1 |
| vuln | combo | 15 | 7 | 8 | 0 | 0 |  46.7% |  46.7% | 5437 | 19903 | 100.0% | 19741 | 206.7 |
| vuln | disguise | 15 | 15 | 0 | 0 | 0 | 100.0% | 100.0% | 797 | 1454 | 100.0% | 1295 | 16.4 |
| vuln | sat3_170 | 15 | 14 | 1 | 0 | 0 |  93.3% |  93.3% | 2917 | 12819 | 100.0% | 12702 | 117.4 |
| vuln | sat3_325 | 15 | 12 | 3 | 0 | 0 |  80.0% |  80.0% | 5068 | 18198 | 100.0% | 18091 | 169.4 |
| safe | original | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 472 | 771 | 100.0% | 661 | 12.7 |
| safe | algebraic | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 615 | 810 | 100.0% | 678 | 15.5 |
| safe | sat3 | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 1749 | 624 | 100.0% | 510 | 10.9 |
| safe | smt | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 646 | 972 | 100.0% | 855 | 15.3 |
| safe | combo | 15 | 0 | 15 | 0 | 0 |   0.0% | - | 5465 | 932 | 100.0% | 804 | 15.8 |

For `vuln` rows the YES rate is the detection rate (higher = transform failed to evade). For `safe` rows it is the false-positive rate. `thinking` = share of calls where the model emitted reasoning (GLM 5.3 reasons on its own even with thinking=off).

## Detection rate per CWE x transform (vuln cases)

| CWE | original | algebraic | sat3 | smt | combo | disguise | sat3_170 | sat3_325 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-121 | 3/3 | 3/3 | 1/3 | 3/3 | 0/3 | 3/3 | 3/3 | 2/3 |
| CWE-190 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 3/3 | 1/3 |
| CWE-22 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 |
| CWE-78 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 2/3 | 3/3 |
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
| cwe121_sbo__vuln__combo | vuln | combo | YES | NO | NO+NO+NO | ✗ |
| cwe121_sbo__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__sat3 | vuln | sat3 | YES | NO | NO+NO+YES | ✗ |
| cwe121_sbo__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe121_sbo__vuln__sat3_325 | vuln | sat3_325 | YES | YES | NO+YES+YES | ✓ |
| cwe121_sbo__vuln__smt | vuln | smt | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__safe__algebraic | safe | algebraic | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__combo | safe | combo | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__original | safe | original | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__sat3 | safe | sat3 | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__safe__smt | safe | smt | NO | NO | NO+NO+NO | ✓ |
| cwe190_intov__vuln__algebraic | vuln | algebraic | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__combo | vuln | combo | YES | NO | NO+NO+NO | ✗ |
| cwe190_intov__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+YES+YES | ✓ |
| cwe190_intov__vuln__sat3_325 | vuln | sat3_325 | YES | NO | YES+NO+NO | ✗ |
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
| cwe78_cmdi__vuln__combo | vuln | combo | YES | NO | NO+YES+NO | ✗ |
| cwe78_cmdi__vuln__disguise | vuln | disguise | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__original | vuln | original | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__sat3 | vuln | sat3 | YES | YES | YES+YES+YES | ✓ |
| cwe78_cmdi__vuln__sat3_170 | vuln | sat3_170 | YES | YES | YES+NO+YES | ✓ |
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

Majority-vote accuracy: 60/65 (92.3%)

