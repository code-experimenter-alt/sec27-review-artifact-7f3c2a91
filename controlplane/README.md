# R-TRAPS versioned control plane

`ActivationStateMachine` enforces:

```text
PREPARED -> EDGE_DELTA_READY -> ACTIVE -> COMPACTED -> RETIRED
```

`ACTIVE` is the directory linearization point and cannot be reached until all
required edges hold signed positive-delta certificates.  Compacted delta
retirement similarly waits for all required compacted-epoch acknowledgments.
Edge crash clears certificate certainty; recovery reconstructs directory and
representation state from the authoritative record.
