# NIST ACVP ML-KEM FIPS 203 corpus

This directory contains the official NIST ACVP internal-projection vectors used
by the blocking Risaal ML-KEM-768 conformance test. The two JSON files were
copied byte-for-byte, without modification, from:

- Repository: <https://github.com/usnistgov/ACVP-Server>
- Pinned commit: `a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324`
- Key generation path:
  `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json`
- Encapsulation/decapsulation path:
  `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json`

The repository-local test verifies each complete fixture's SHA-256 digest
before parsing it. A changed, truncated, replaced, or empty fixture therefore
fails closed before any vector is executed.

## Integrity

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `ML-KEM-keyGen-FIPS203/internalProjection.json` | 558,841 | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` |
| `ML-KEM-encapDecap-FIPS203/internalProjection.json` | 1,465,634 | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |

## Blocking ML-KEM-768 coverage

The source files also contain ML-KEM-512 and ML-KEM-1024 data. Risaal's
production primitive is ML-KEM-768, so
`../../mlkem_768_acvp_test.dart` executes exactly these 80 cases:

| Operation | ACVP type | Cases |
| --- | --- | ---: |
| Key generation | AFT | 25 |
| Encapsulation plus round-trip decapsulation | AFT | 25 |
| Decapsulation, including implicit rejection | VAL | 10 |
| Encapsulation-key validation | VAL | 10 |
| Decapsulation-key validation | VAL | 10 |
| **Total** |  | **80** |

The runner has `@Retry(0)`, requires the exact corpus/group/case counts, and
compares byte results through an aggregate difference only. It never prints
keys, seeds, ciphertexts, shared secrets, or vector bytes.

Run the gate from `packages/risaal_crypto`:

```bash
dart test test/mlkem_768_acvp_test.dart
```

## NIST notice

NIST-developed software is provided by NIST as a public service. You may use,
copy, and distribute copies of the software in any medium, provided that you
keep intact this entire notice. You may improve, modify, and create derivative
works of the software or any portion of the software, and you may copy and
distribute such modifications or works. Modified works should carry a notice
stating that you changed the software and should note the date and nature of
any such change. Please explicitly acknowledge the National Institute of
Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY
OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST
NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES
NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR
THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and
distributing the software and you assume all risks associated with its use,
including but not limited to the risks and costs of program errors, compliance
with applicable laws, damage to or loss of data, programs or equipment, and
the unavailability or interruption of operation. This software is not intended
to be used in any situation where a failure could cause risk of injury or
damage to property. The software developed by NIST employees is not subject to
copyright protection within the United States.
