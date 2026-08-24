# Global Definitions and Randomness Model

This notation governs T1-T5. A theorem about a realized trace conditions on the
constructed state `theta`; probability then refers only to an explicitly named
query distribution or experiment. Construction randomness is never silently
reused as request-level randomness.

| Symbol | Meaning |
|---|---|
| `theta` | fully realized positive-screen state, including seeds and layout |
| `P_theta(x)` | deterministic one-sided predicate after construction; 1 means forward |
| `x` | exact credential tuple bound to immutable account generation and credential version |
| `G=(g_1,...,g_r)` | ordered offline/online guess sequence, with first correct guess `g_r` |
| `C_P`, `C_H` | cheap-screen and slow-verifier costs |
| `C_confirm` | zero or one final slow confirmation cost |
| `Q_on`, `Q_off` | declared online and offline invalid-query distributions |
| `Phi_on`, `Phi_off` | expected realized predicate value under those distributions |
| `c_x` | request multiplicity of invalid tuple `x` in a realized trace |
| `e_x` | observed cache eviction/expiration episodes after first confirmation |
| `f_x` | extra backend executions caused by races beyond the singleflight guarantee |
| `b`, `B` | fine score bin and total fine-bin count |
| `I` | contiguous interval of fine bins selected as a region |
| `N_I` | represented-member occupancy of interval `I` |
| `U_I` | expected uncached distinct-invalid/backend-miss episodes in `I` |
| `c_I`, `W_I` | verifier cost and online weight, with `W_I=c_I U_I` |
| `D_I` | selected post-compromise invalid-guess weight |
| `beta_I` | substrate constant in `epsilon_I=exp(-beta_I m_I/N_I)` |
| `epsilon_I`, `m_I` | false-positive probability and positive-screen bits for `I` |
| `M`, `Gamma` | total positive memory and compromise-work floor |
| `lambda`, `nu` | memory and work-floor Lagrange multipliers |
| `q`, `pi` | negative-cache quota and admission/eviction policy |
| `C_I(m,q,pi)` | seeded realized replay cost for one joint interval option |
| `p_l`, `k_l`, `phi_l` | layer bit-set probability, integer probes, and ideal hit probability |
| `R_l` | probability that a nonmember query reaches layer `l` |

## Adversary and exposure qualifiers

- T1 conditions on a declared exposure profile and an ordered guess sequence. It
  does not assume the attacker samples i.i.d. guesses unless a distributional
  corollary explicitly says so.
- T2 is deterministic for a realized request trace, including concurrent arrival
  groups and observed cache episodes.
- T3 permits delayed, duplicated, and reordered messages, edge crashes, account
  reuse, and concurrent rotation. Cryptographic collision resistance is the only
  probabilistic exception to exact-key separation.
- T4 uses training/validation estimates only. Test data does not define bins,
  weights, constraints, option tables, or selected designs.
- T5 distinguishes an ideal independent-bit approximation from the exact finite
  bit array and the actual early-exit probe loop.

## Screen semantics

All implementations use one convention: positive means "possibly represented,
forward to the backend" and negative means "definitely not represented." Every
represented current credential must be positive in every state that is allowed
to reject locally. Uncertain state is not a negative result; it fails open.
