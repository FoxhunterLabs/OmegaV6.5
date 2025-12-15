# OmegaV6.5 — Deterministic Governance Kernel

**OmegaV6.5** is a deterministic, non-actuating oversight kernel for autonomous and semi-autonomous systems. It observes, evaluates, and proposes actions under strict integrity guarantees—while keeping humans as the final authority.

---

## Core Principles

- **Determinism First**  
  Replayable execution with self-tests. Identical inputs yield identical audit, memory, and signatures.

- **Hard Integrity Boundary**  
  Audit + memory chains hash *only* integrity payloads. Timing and UI data are observability-only.

- **Non-Actuating by Design**  
  Omega never controls hardware. It analyzes, recommends, and gates—humans decide.

- **Epistemic Honesty**  
  Explicit uncertainty modeling (“knowledge holes”) blocks unsafe recommendations.

---

## What It Does

- Single-pass **risk + invariant evaluation** (no two-phase artifacts)
- **Tamper-evident audit spine** and **memory chain**
- Deterministic clock and per-asset RNG seeding
- Human-gated **Governor** with pressure, cooldowns, and withdrawal logic
- Counterfactual risk deltas (“what would reduce risk most?”)
- Safe **monitor DSL** for temporal and policy rules
- Exportable **replay capsules** + built-in determinism self-test

---

## What It Is Not

- ❌ Not an autonomy controller  
- ❌ Not real-time actuation software  
- ❌ Not a black-box ML policy  

Omega is an **oversight OS**, not a driver.

---

## Quick Start

```bash
streamlit run app.py
