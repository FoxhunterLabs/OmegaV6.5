from __future__ import annotations
"""
OmegaV6.5 – Unified Autonomous Oversight Kernel
(deterministic integrity, replayable, non-actuating)

Run:
streamlit run app.py

V6.5 focus:
- Hard Integrity vs Observability boundary
* tick_ms recorded but excluded from hashes + decisions/invariants
- Single-pass invariant+decision evaluation (no two-phase artifacts)
- Audit + Memory chains hash only integrity payloads
- Determinism self-test compares per-asset determinism signatures + memory tail hashes

Omega never actuates; it only observes, analyzes, and proposes.
Humans remain the final authority.
"""

import hashlib
import json
import random
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from statistics import mean

from typing import Any, Dict, List, Optional, Protocol, Tuple

import pandas as pd
import streamlit as st

#
=============================================================================
# Constants + Integrity Boundary
#
=============================================================================

KERNEL_VERSION = "OmegaV6.5"
CAPSULE_SCHEMA_VERSION = 7 # bumped for boundary changes

# Any field listed here is EXCLUDED from integrity hashing.
OBSERVABILITY_FIELDS = {
"tick_ms",
"duration_ms",
"last_tick_ms",
"perf",
"ui",
}

# Canonical float rounding for integrity hashing (review-proofing)
CANON_FLOAT_DIGITS = 6

# Deterministic timestamp stride per tick (ms)

TICK_STRIDE_MS = 10

def canonicalize(x: Any) -> Any:
"""
Canonicalize objects before hashing:
- round floats to fixed digits (prevents platform/py-version float repr drift)
- sort dict keys recursively
- remove OBSERVABILITY_FIELDS recursively
"""
if isinstance(x, float):
return round(x, CANON_FLOAT_DIGITS)
if isinstance(x, dict):
# drop observability keys at every nesting level
keys = [k for k in x.keys() if k not in OBSERVABILITY_FIELDS]
return {k: canonicalize(x[k]) for k in sorted(keys)}
if isinstance(x, list):
return [canonicalize(v) for v in x]
if isinstance(x, tuple):
return [canonicalize(v) for v in x]
return x

def sha256_bytes(data: bytes) -> str:
return hashlib.sha256(data).hexdigest()

def sha256_json(obj: Any) -> str:
obj2 = canonicalize(obj)

return sha256_bytes(json.dumps(obj2, sort_keys=True, separators=(",", ":"),
ensure_ascii=True).encode("utf-8"))

def integrity_dict(d: Dict[str, Any]) -> Dict[str, Any]:
return {k: v for k, v in d.items() if k not in OBSERVABILITY_FIELDS}

def clamp(x: float, lo: float, hi: float) -> float:
return max(lo, min(hi, x))

def _u32(x: int) -> int:
return x & 0xFFFFFFFF

def tick_rng(seed: int, tick: int, salt: int = 0) -> random.Random:
mixed = _u32(seed ^ _u32(tick * 0x9E3779B9) ^ _u32(salt * 0x85EBCA6B))
return random.Random(mixed)

def derive_asset_seed(session_id: str, asset_key: str) -> int:
h = sha256_json({"session_id": session_id, "asset_key": asset_key})
return (int(h[:8], 16) & 0x7FFFFFFF) or 1

#
=============================================================================
# Deterministic clock (tick-derived timestamps)
#
=============================================================================

@dataclass

class DeterministicClockState:
base_epoch_ms: int

class DeterministicClock:
"""
Deterministic timestamps for integrity artifacts:
- base derived from session_id
- timestamp derived from (tick, local_seq) NOT call count
"""

def __init__(self, session_id: str, state: Optional[DeterministicClockState] = None) -> None:
if state is not None:
self.base_epoch_ms = int(state.base_epoch_ms)
return

anchor = datetime(2025, 1, 1, tzinfo=timezone.utc)
anchor_ms = int(anchor.timestamp() * 1000)
jitter = int(sha256_json({"sid": session_id, "k": "clock"})[:8], 16) % (365 * 24 * 3600 * 1000)
self.base_epoch_ms = anchor_ms + jitter

def ts(self, tick: int, local_seq: int = 0) -> str:
ms = self.base_epoch_ms + int(tick) * TICK_STRIDE_MS + int(local_seq)
dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def to_state(self) -> Dict[str, Any]:

return asdict(DeterministicClockState(self.base_epoch_ms))

@staticmethod
def from_state(session_id: str, state: Dict[str, Any]) -> "DeterministicClock":
return DeterministicClock(session_id, DeterministicClockState(**state))

#
=============================================================================
# Audit spine (integrity-only hashing)
#
=============================================================================

@dataclass
class AuditEntry:
seq: int
timestamp: str
kind: str
payload: Dict[str, Any] # integrity payload only
prev_hash: str
hash: str
session_id: str
observability: Dict[str, Any] = field(default_factory=dict)

class AuditSpine:
"""
Tamper-evident append-only chain.
Hash includes ONLY integrity payloads (canonicalized).

Observability metadata stored but excluded from hash.
"""

def __init__(self, clock: DeterministicClock, session_id: str) -> None:
self.session_id = session_id
self.clock = clock
self.genesis_hash = sha256_json({"genesis": session_id, "kernel": KERNEL_VERSION,
"schema": CAPSULE_SCHEMA_VERSION})
self.prev_hash = self.genesis_hash
self.seq = 0
self.entries: List[AuditEntry] = []

def log(
self,
tick: int,
kind: str,
payload: Dict[str, Any],
observability: Optional[Dict[str, Any]] = None
) -> AuditEntry:
self.seq += 1
ts = self.clock.ts(tick=tick, local_seq=self.seq)

ip = integrity_dict(payload)
body = {
"session_id": self.session_id,
"seq": self.seq,

"timestamp": ts,
"kind": kind,
"payload": ip,
"prev_hash": self.prev_hash,
}
h = sha256_json(body)

e = AuditEntry(
seq=self.seq,
timestamp=ts,
kind=kind,
payload=canonicalize(ip),
prev_hash=self.prev_hash,
hash=h,
session_id=self.session_id,
observability=(observability or {}),
)
self.prev_hash = h
self.entries.append(e)
return e

def tail(self, n: int = 40) -> List[AuditEntry]:
return self.entries[-n:]

def verify_chain(self) -> Tuple[bool, Optional[int]]:
prev = self.genesis_hash

for idx, e in enumerate(self.entries):
body = {
"session_id": e.session_id,
"seq": e.seq,
"timestamp": e.timestamp,
"kind": e.kind,
"payload": e.payload,
"prev_hash": prev,
}
expected = sha256_json(body)
if e.prev_hash != prev or e.hash != expected:
return False, idx
prev = e.hash
return True, None

def to_json(self) -> str:
return json.dumps([asdict(e) for e in self.entries], indent=2, sort_keys=True)

#
=============================================================================
# World model
#
=============================================================================

@dataclass(frozen=True)
class AssetId:
site: str

asset: str
def key(self) -> str:
return f"{self.site}:{self.asset}"

class GovernorMode:
SHADOW = "shadow"
TRAINING = "training"
LIVE = "live"

@dataclass
class Pose:
x: float = 0.0
y: float = 0.0
heading_deg: float = 0.0
zone: str = "zone-A"

@dataclass
class FaultProfile:
drift_spike_prob: float = 0.0
dropout_prob: float = 0.0
freeze_prob: float = 0.0
negative_speed_prob: float = 0.0
contradictory_prob: float = 0.0
timestamp_anomaly_prob: float = 0.0

@dataclass

class SensorChannel:
name: str
value: float
last_true_value: float
last_update_tick: int
ok: bool = True
stale: bool = False
frozen: bool = False
contradictory: bool = False
timestamp_future: bool = False

@dataclass
class SensorSuite:
drift: List[SensorChannel]
speed: List[SensorChannel]
stability: List[SensorChannel]

def default_sensor_suite() -> SensorSuite:
return SensorSuite(
drift=[SensorChannel("drift_imu", 0.0, 0.0, 0),
SensorChannel("drift_camera", 0.0, 0.0, 0),
SensorChannel("drift_fused", 0.0, 0.0, 0)],
speed=[SensorChannel("speed_encoder", 40.0, 40.0, 0),
SensorChannel("speed_gnss", 40.0, 40.0, 0)],
stability=[SensorChannel("stability_estimator", 100.0, 100.0, 0),
SensorChannel("stability_redundant", 100.0, 100.0, 0)],

)

@dataclass
class VehicleState:
drift_deg: float = 0.0
stability: float = 100.0
speed_kph: float = 40.0
commanded_speed_kph: float = 40.0

@dataclass
class WorldState:
asset: AssetId
tick: int = 0
mode: str = GovernorMode.SHADOW
vehicle: VehicleState = field(default_factory=VehicleState)
pose: Pose = field(default_factory=Pose)
sensors: SensorSuite = field(default_factory=default_sensor_suite)

def to_dict(self) -> Dict[str, Any]:
return asdict(self)

MAX_PROX_DISTANCE = 200.0
MIN_CONVOY_SPACING = 20.0
ZONE_CONFLICT_THRESHOLD = 10.0

@dataclass

class InteractionSummary:
nearest_distance: float
same_zone_conflict: bool
convoy_spacing_bad: bool

def simulate_dynamics(world: WorldState, seed: int, faults: FaultProfile) -> WorldState:
rng = tick_rng(seed, world.tick, salt=1)
v = world.vehicle

cmd_delta = rng.uniform(-2.0, 2.0)
v.commanded_speed_kph = clamp(v.commanded_speed_kph + cmd_delta, 0.0, 80.0)

lag_limit = 5.0
diff = clamp(v.commanded_speed_kph - v.speed_kph, -lag_limit, lag_limit)
v.speed_kph = clamp(v.speed_kph + diff, -40.0, 80.0)

v.drift_deg = clamp(v.drift_deg + rng.uniform(-1.5, 1.5), -90.0, 90.0)
v.stability = clamp(v.stability + rng.uniform(-3.0, 2.0), 0.0, 100.0)

if rng.random() < faults.drift_spike_prob:
v.drift_deg = clamp(v.drift_deg + rng.uniform(-20.0, 20.0), -90.0, 90.0)
if rng.random() < faults.negative_speed_prob:
v.speed_kph = -abs(v.speed_kph)

dt = 1.0
world.pose.x += (v.speed_kph / 3.6) * dt

zone_cycle = abs(world.pose.x) % 200.0
world.pose.zone = "zone-A" if zone_cycle < 100.0 else "zone-B"
return world

def update_sensors(world: WorldState, seed: int, faults: FaultProfile) -> None:
rng = tick_rng(seed, world.tick, salt=2)

def update_channel(ch: SensorChannel, true_val: float, noise_span: float) -> None:
if ch.frozen and rng.random() < 0.05:
ch.frozen = False

if not ch.frozen:
if rng.random() < faults.dropout_prob:
ch.ok = False
else:
ch.ok = True
ch.value = true_val + rng.uniform(-noise_span, noise_span)
ch.last_true_value = true_val
ch.last_update_tick = world.tick

if rng.random() < faults.contradictory_prob:
ch.value = ch.value + rng.uniform(20.0, 40.0) * (1.0 if rng.random() < 0.5 else -1.0)
ch.contradictory = True
else:
ch.contradictory = False

if rng.random() < faults.freeze_prob:
ch.frozen = True

ch.timestamp_future = False
if rng.random() < faults.timestamp_anomaly_prob:
offset = rng.randint(3, 10)
if rng.random() < 0.5:
ch.last_update_tick = world.tick - offset
else:
ch.last_update_tick = world.tick + offset
ch.timestamp_future = True

ch.stale = (world.tick - ch.last_update_tick) > 3

v = world.vehicle
for ch in world.sensors.drift:
update_channel(ch, v.drift_deg, 1.5)
for ch in world.sensors.speed:
update_channel(ch, v.speed_kph, 2.5)
for ch in world.sensors.stability:
update_channel(ch, v.stability, 5.0)

def compute_interactions(worlds: Dict[str, WorldState]) -> Dict[str, InteractionSummary]:
result: Dict[str, InteractionSummary] = {}
keys = sorted(list(worlds.keys())) # stable ordering

for key in keys:
w = worlds[key]
x = w.pose.x
zone = w.pose.zone

nearest = float("inf")
same_zone_conflict = False

for other_key in keys:
if other_key == key:
continue
w2 = worlds[other_key]
if w2.asset.site != w.asset.site:
continue
dx = abs(w2.pose.x - x)
nearest = min(nearest, dx)
if w2.pose.zone == zone and dx < ZONE_CONFLICT_THRESHOLD:
same_zone_conflict = True

if nearest == float("inf"):
nearest = MAX_PROX_DISTANCE
convoy_spacing_bad = nearest < MIN_CONVOY_SPACING

result[key] = InteractionSummary(nearest_distance=nearest,
same_zone_conflict=same_zone_conflict, convoy_spacing_bad=convoy_spacing_bad)
return result

#
=============================================================================
# Sensor metrics + epistemic
#
=============================================================================

@dataclass
class SensorMetrics:
sensor_health: float
stale_fraction: float
contradictory_fraction: float
dropout_fraction: float
frozen_fraction: float
future_timestamp_fraction: float

def compute_sensor_metrics(sensors: SensorSuite) -> SensorMetrics:
channels = sensors.drift + sensors.speed + sensors.stability
total = max(1, len(channels))
stale = sum(1 for c in channels if c.stale)
contradictory = sum(1 for c in channels if c.contradictory)
dropout = sum(1 for c in channels if not c.ok)
frozen = sum(1 for c in channels if c.frozen)
future_ts = sum(1 for c in channels if c.timestamp_future)

bad = sum(1 for c in channels if (not c.ok) or c.stale or c.contradictory or c.timestamp_future)
sensor_health = clamp(1.0 - bad / float(total), 0.0, 1.0)

return SensorMetrics(
sensor_health=sensor_health,
stale_fraction=stale / float(total),
contradictory_fraction=contradictory / float(total),
dropout_fraction=dropout / float(total),
frozen_fraction=frozen / float(total),
future_timestamp_fraction=future_ts / float(total),
)

#
=============================================================================
# Safety kernel
#
=============================================================================

@dataclass
class RiskConfig:
drift_watch_deg: float = 10.0
drift_hold_deg: float = 25.0
drift_stop_deg: float = 45.0
stability_watch_min: float = 70.0
stability_hold_min: float = 55.0
stability_stop_min: float = 40.0

@dataclass
class RiskContext:

sensor: SensorMetrics
proximity: float
same_zone_conflict: bool

@dataclass
class RiskState:
last_band: str = "LOW"
stable_ticks_in_band: int = 0
history_risk_sum: float = 0.0
history_risk_count: int = 0

@dataclass
class RiskPacket:
tick: int
risk: float
band: str
epistemic: float
knowledge_hole: bool
features: Dict[str, float]
contributions: Dict[str, float]
counterfactual_deltas: Dict[str, float]

class SafetyKernel:
def __init__(self, cfg: RiskConfig) -> None:
self.cfg = cfg
self._severity_rank = {"LOW": 0, "WATCH": 1, "HOLD": 2, "STOP": 3}

@staticmethod
def _median(values: List[float]) -> float:
s = sorted(values)
return s[len(s)//2]

def _fuse_channels(self, channels: List[SensorChannel], default: float) -> Tuple[float, float,
int]:
usable = [c.value for c in channels if c.ok and (not c.stale) and (not c.timestamp_future)]
if not usable:
return default, 0.0, 0
med = self._median(usable)
spread = (max(usable) - min(usable)) if len(usable) > 1 else 0.0
return med, spread, len(usable)

def _compute_epistemic(self, ctx: RiskContext, drift_spread: float, speed_spread: float,
stab_spread: float) -> float:
drift_u = clamp(drift_spread / 15.0, 0.0, 1.0)
speed_u = clamp(speed_spread / 25.0, 0.0, 1.0)
stab_u = clamp(stab_spread / 40.0, 0.0, 1.0)

s = ctx.sensor
dq = (
(1.0 - s.sensor_health) * 0.35
+ s.stale_fraction * 0.15
+ s.contradictory_fraction * 0.20
+ s.dropout_fraction * 0.10

+ s.frozen_fraction * 0.10
+ s.future_timestamp_fraction * 0.30
)
spread = 0.25 * drift_u + 0.20 * speed_u + 0.20 * stab_u
return clamp(dq + spread, 0.0, 1.0)

def _compute_risk_scalar(
self,
drift_abs: float,
stability: float,
speed_kph: float,
ctx: RiskContext,
epistemic: float,
state: RiskState,
credit: float,
) -> Tuple[float, Dict[str, float]]:
drift_norm = clamp(drift_abs / self.cfg.drift_stop_deg, 0.0, 1.0)
stability_norm = 1.0 - clamp((self.cfg.stability_stop_min - stability) / 60.0, 0.0, 1.0)
speed_norm = clamp(max(0.0, speed_kph) / 120.0, 0.0, 1.0)

same_zone = 1.0 if ctx.same_zone_conflict else 0.0

contrib: Dict[str, float] = {}
contrib["drift"] = 0.45 * drift_norm
contrib["stability"] = 0.35 * (1.0 - stability_norm)
contrib["speed"] = 0.20 * speed_norm

contrib["sensor_health"] = (1.0 - ctx.sensor.sensor_health) * 0.25
contrib["proximity"] = ctx.proximity * 0.30
contrib["zone_conflict"] = same_zone * 0.15
contrib["stale"] = ctx.sensor.stale_fraction * 0.10
contrib["contradictory"] = ctx.sensor.contradictory_fraction * 0.15
contrib["epistemic"] = epistemic * 0.12

credit_adj = clamp(-credit / 500.0, -0.10, 0.10)
contrib["credit_debt"] = credit_adj

risk = sum(contrib.values())

if state.history_risk_count > 0:
avg_hist = state.history_risk_sum / state.history_risk_count
if avg_hist > risk:
hist_bias = 0.15 * (avg_hist - risk)
contrib["history_bias"] = hist_bias
risk += hist_bias
else:
contrib["history_bias"] = 0.0
else:
contrib["history_bias"] = 0.0

return clamp(risk, 0.0, 1.0), contrib

def _band_from_risk(self, risk: float) -> str:

if risk >= 0.80: return "STOP"
if risk >= 0.55: return "HOLD"
if risk >= 0.30: return "WATCH"
return "LOW"

def _apply_hysteresis(self, base_band: str, state: RiskState) -> str:
old = state.last_band or "LOW"
rank = self._severity_rank
HYST = 3

if rank[base_band] > rank[old]:
band = base_band
state.stable_ticks_in_band = 0
elif rank[base_band] < rank[old]:
if state.stable_ticks_in_band >= HYST:
band = base_band
state.stable_ticks_in_band = 0
else:
band = old
state.stable_ticks_in_band += 1
else:
band = base_band
state.stable_ticks_in_band += 1

state.last_band = band
return band

def _counterfactual_deltas(
self,
drift_abs: float,
stability: float,
speed_kph: float,
ctx: RiskContext,
epistemic: float,
state_for_cf: RiskState,
credit: float,
) -> Dict[str, float]:
base, _ = self._compute_risk_scalar(drift_abs, stability, speed_kph, ctx, epistemic,
state_for_cf, credit)

def risk_with(**over: Any) -> float:
da = over.get("drift_abs", drift_abs)
stv = over.get("stability", stability)
sp = over.get("speed_kph", speed_kph)
cx = over.get("ctx", ctx)
ep = over.get("epistemic", epistemic)
cr = over.get("credit", credit)
tmp = RiskState(
last_band=state_for_cf.last_band,
stable_ticks_in_band=state_for_cf.stable_ticks_in_band,
history_risk_sum=state_for_cf.history_risk_sum,
history_risk_count=state_for_cf.history_risk_count,

)
r, _ = self._compute_risk_scalar(da, stv, sp, cx, ep, tmp, cr)
return r

deltas = {
"drift_to_zero": base - risk_with(drift_abs=0.0),
"speed_to_zero": base - risk_with(speed_kph=0.0),
"stability_to_healthy": base - risk_with(stability=100.0),
"sensor_health_to_1": base - risk_with(ctx=RiskContext(
sensor=SensorMetrics(
sensor_health=1.0,
stale_fraction=ctx.sensor.stale_fraction,
contradictory_fraction=ctx.sensor.contradictory_fraction,
dropout_fraction=ctx.sensor.dropout_fraction,
frozen_fraction=ctx.sensor.frozen_fraction,
future_timestamp_fraction=ctx.sensor.future_timestamp_fraction,
),
proximity=ctx.proximity,
same_zone_conflict=ctx.same_zone_conflict,
)),
"proximity_to_0": base - risk_with(ctx=RiskContext(sensor=ctx.sensor, proximity=0.0,
same_zone_conflict=False)),
"epistemic_to_0": base - risk_with(epistemic=0.0),
"credit_to_0": base - risk_with(credit=0.0),
}
return {k: round(v, 4) for k, v in deltas.items()}

def eval(
self,
world: WorldState,
ctx: RiskContext,
state: RiskState,
credit: float,
epistemic_threshold: float,
) -> RiskPacket:
v = world.vehicle
fused_drift, drift_spread, _ = self._fuse_channels(world.sensors.drift, v.drift_deg)
fused_speed, speed_spread, _ = self._fuse_channels(world.sensors.speed, v.speed_kph)
fused_stab, stab_spread, _ = self._fuse_channels(world.sensors.stability, v.stability)

drift_abs = abs(fused_drift)
stability = fused_stab
speed = fused_speed

epistemic = self._compute_epistemic(ctx, drift_spread, speed_spread, stab_spread)
knowledge_hole = epistemic >= epistemic_threshold

risk, contrib = self._compute_risk_scalar(drift_abs, stability, speed, ctx, epistemic, state,
credit)
state.history_risk_sum += risk
state.history_risk_count += 1

base_band = self._band_from_risk(risk)
band = self._apply_hysteresis(base_band, state)

features = {
"drift_abs": round(drift_abs, 3),
"stability": round(stability, 3),
"speed_kph": round(speed, 3),
"sensor_health": round(ctx.sensor.sensor_health, 3),
"stale_fraction": round(ctx.sensor.stale_fraction, 3),
"contradictory_fraction": round(ctx.sensor.contradictory_fraction, 3),
"dropout_fraction": round(ctx.sensor.dropout_fraction, 3),
"frozen_fraction": round(ctx.sensor.frozen_fraction, 3),
"future_ts_fraction": round(ctx.sensor.future_timestamp_fraction, 3),
"proximity": round(ctx.proximity, 3),
"same_zone_conflict": 1.0 if ctx.same_zone_conflict else 0.0,
"drift_spread": round(drift_spread, 3),
"speed_spread": round(speed_spread, 3),
"stability_spread": round(stab_spread, 3),
"epistemic": round(epistemic, 3),
"credit": round(credit, 3),
}

cf_state = RiskState(
last_band=state.last_band,
stable_ticks_in_band=state.stable_ticks_in_band,
history_risk_sum=state.history_risk_sum,

history_risk_count=state.history_risk_count,
)
cfd = self._counterfactual_deltas(drift_abs, stability, speed, ctx, epistemic, cf_state, credit)

return RiskPacket(
tick=world.tick,
risk=risk,
band=band,
epistemic=epistemic,
knowledge_hole=knowledge_hole,
features=features,
contributions={k: round(v, 4) for k, v in contrib.items()},
counterfactual_deltas=cfd,
)

#
=============================================================================
# Invariants (NO real timing)
#
=============================================================================

@dataclass
class Invariants:
drift_max_live: float
stability_min_live: float

@dataclass

class InvariantProof:
invariant_id: str
satisfied: bool
margin: float
confidence: float
evidence_hashes: List[str]

def evaluate_invariants(
inv: Invariants,
world: WorldState,
epistemic: float,
evidence_bundle: Dict[str, Any],
) -> Tuple[List[InvariantProof], List[str]]:
v = world.vehicle
proofs: List[InvariantProof] = []
violated: List[str] = []
conf = clamp(1.0 - epistemic, 0.05, 1.0)

margin_drift = inv.drift_max_live - abs(v.drift_deg)
sat_drift = margin_drift >= 0.0
if not sat_drift: violated.append("drift_exceeds_live_max")
proofs.append(InvariantProof(
invariant_id="drift_max_live",
satisfied=sat_drift,
margin=round(margin_drift, 3),
confidence=round(conf, 3),

evidence_hashes=[sha256_json({"drift_deg": v.drift_deg, "bundle": evidence_bundle})],
))

margin_stab = v.stability - inv.stability_min_live
sat_stab = margin_stab >= 0.0
if not sat_stab: violated.append("stability_below_live_min")
proofs.append(InvariantProof(
invariant_id="stability_min_live",
satisfied=sat_stab,
margin=round(margin_stab, 3),
confidence=round(conf, 3),
evidence_hashes=[sha256_json({"stability": v.stability, "bundle": evidence_bundle})],
))

return proofs, violated

#
=============================================================================
# Policy + Governor
#
=============================================================================

@dataclass
class RiskPolicy:
id: str
risk_cfg: RiskConfig
invariants: Invariants

band_to_action: Dict[str, str]
human_gate_bands_live: Tuple[str, ...]
avalon_risk_cap: float
epistemic_threshold: float
source_hash: str

DEFAULT_POLICY_DICT = {
"id": "policy_demo_v6_5",
"risk_cfg": {
"drift_watch_deg": 10.0,
"drift_hold_deg": 25.0,
"drift_stop_deg": 45.0,
"stability_watch_min": 70.0,
"stability_hold_min": 55.0,
"stability_stop_min": 40.0,
},
"invariants": {"drift_max_live": 30.0, "stability_min_live": 60.0},
"band_to_action": {"LOW": "normal", "WATCH": "cautious", "HOLD": "stop_safe", "STOP":
"stop_safe"},
"human_gate_bands_live": ["HOLD", "STOP"],
"avalon_risk_cap": 65.0,
"epistemic_threshold": 0.75,
}

def build_policy(cfg: Dict[str, Any]) -> RiskPolicy:
rp = RiskPolicy(

id=str(cfg["id"]),
risk_cfg=RiskConfig(**cfg["risk_cfg"]),
invariants=Invariants(**cfg["invariants"]),
band_to_action=dict(cfg["band_to_action"]),
human_gate_bands_live=tuple(cfg.get("human_gate_bands_live", ["HOLD", "STOP"])),
avalon_risk_cap=float(cfg.get("avalon_risk_cap", 65.0)),
epistemic_threshold=float(cfg.get("epistemic_threshold", 0.75)),
source_hash=sha256_json(cfg),
)
return rp

@dataclass
class HumanGateState:
gate_id: str
asset_key: str
tick: int
band: str
mode: str
proposed_action: str
severity: str
purpose: str = "action" # action | brain_admission | rule_sign
related_id: str = ""
stage: int = 1
required_role: str = "supervisor"
approved: Optional[bool] = None
operator_id: Optional[str] = None

note: str = ""
created_at: str = ""
expires_at_tick: int = 0
resolved_at: Optional[str] = None
dedupe_key: str = ""

@dataclass
class GatePressureConfig:
window_ticks: int = 25
max_gates_in_window: int = 6
cooldown_ticks: int = 4
withdrawal_threshold: float = 0.90
pressure_floor_for_cooldown: float = 0.65

@dataclass
class Decision:
tick: int
action: str
proposed_action: str
band: str
epistemic: float
knowledge_hole: bool
requires_human_gate: bool
human_gate_id: Optional[str]
invariants_violated: List[str]
invariant_proofs: List[Dict[str, Any]]

gate_pressure: float
withdrawal_recommended: bool
in_cooldown: bool
reason_chain: List[Dict[str, Any]]

class Governor:
def __init__(self, policy: RiskPolicy, mode: str, asset_key: str, clock: DeterministicClock) ->
None:
self.policy = policy
self.mode = mode
self.asset_key = asset_key
self.clock = clock

self._next_gate_id = 1
self._gates: Dict[str, HumanGateState] = {}
self._gate_events: List[int] = []
self._cooldown_until_tick: int = 0
self._pressure_sustained_ticks: int = 0
self.gate_pressure_cfg = GatePressureConfig()
self._severity_rank = {"LOW": 0, "WATCH": 1, "HOLD": 2, "STOP": 3}

def _dedupe_key(self, purpose: str, related_id: str, band: str, stage: int) -> str:
return sha256_json({"asset": self.asset_key, "purpose": purpose, "related": related_id,
"band": band, "stage": stage})[:16]

def _has_active_dedupe(self, dkey: str) -> bool:
return any(g.dedupe_key == dkey and g.approved is None for g in self._gates.values())

def _new_gate(self, band: str, tick: int, proposed: str, purpose: str, related_id: str, stage: int,
expires_in_ticks: int) -> HumanGateState:
dkey = self._dedupe_key(purpose, related_id, band, stage)
if self._has_active_dedupe(dkey):
for g in self._gates.values():
if g.dedupe_key == dkey and g.approved is None:
return g

gid = f"{self.asset_key}-gate-{self._next_gate_id:04d}"
local_seq = self._next_gate_id
self._next_gate_id += 1
severity = "critical" if band == "STOP" else "high"
required_role = "lead" if stage >= 2 else "supervisor"

gate = HumanGateState(
gate_id=gid,
asset_key=self.asset_key,
tick=tick,
band=band,
mode=self.mode,
proposed_action=proposed,
severity=severity,
purpose=purpose,
related_id=related_id,
stage=stage,

required_role=required_role,
created_at=self.clock.ts(tick=tick, local_seq=local_seq),
expires_at_tick=tick + expires_in_ticks,
dedupe_key=dkey,
)
self._gates[gid] = gate
if purpose in ("action", "brain_admission"):
self._gate_events.append(tick)
return gate

def _update_gate_expirations(self, current_tick: int) -> None:
for g in list(self._gates.values()):
if g.approved is None and current_tick > g.expires_at_tick:
g.approved = False
g.note = (g.note or "") + " [auto-expired]"
g.resolved_at = self.clock.ts(tick=current_tick, local_seq=1)
if g.stage < 3 and g.purpose in ("action", "brain_admission"):
new_stage = g.stage + 1
new_expires = 3 if new_stage >= 2 else 5
self._new_gate(g.band, current_tick, g.proposed_action, g.purpose, g.related_id,
new_stage, new_expires)

def _active_gates(self, purpose: Optional[str] = None) -> List[HumanGateState]:
active = [g for g in self._gates.values() if g.approved is None]
return active if purpose is None else [g for g in active if g.purpose == purpose]

def _select_current_gate(self, purpose: str) -> Optional[HumanGateState]:
active = self._active_gates(purpose)
if not active:
return None
def score(g: HumanGateState) -> Tuple[int, int, int]:
return (self._severity_rank.get(g.band, 0), g.stage, g.tick)
return max(active, key=score)

def find_gate_by_related(self, purpose: str, related_id: str) -> Optional[HumanGateState]:
for g in self._gates.values():
if g.purpose == purpose and g.related_id == related_id:
return g
return None

def create_gate(self, band: str, tick: int, proposed_action: str, purpose: str, related_id: str,
stage: int = 1, expires_in_ticks: int = 10) -> HumanGateState:
return self._new_gate(band, tick, proposed_action, purpose, related_id, stage,
expires_in_ticks)

def gate_pressure(self, current_tick: int) -> float:
cfg = self.gate_pressure_cfg
self._gate_events = [t for t in self._gate_events if (current_tick - t) <= cfg.window_ticks]
return float(clamp(len(self._gate_events) / float(max(1, cfg.max_gates_in_window)), 0.0,
1.5))

def _update_cooldown(self, current_tick: int, pressure: float) -> bool:
cfg = self.gate_pressure_cfg

if pressure >= cfg.pressure_floor_for_cooldown:
self._pressure_sustained_ticks += 1
else:
self._pressure_sustained_ticks = max(0, self._pressure_sustained_ticks - 1)

if self._pressure_sustained_ticks >= 4 and current_tick >= self._cooldown_until_tick:
self._cooldown_until_tick = current_tick + cfg.cooldown_ticks
return current_tick < self._cooldown_until_tick

def evaluate(
self,
risk: RiskPacket,
world: WorldState,
invariant_proofs: List[InvariantProof],
invariants_violated: List[str],
) -> Decision:
self._update_gate_expirations(world.tick)
reasons: List[Dict[str, Any]] = []

proposed = self.policy.band_to_action.get(risk.band, "stop_safe")
reasons.append({"rule": "band_to_action", "band": risk.band, "proposed": proposed,
"risk": round(risk.risk, 3)})

if self.mode == GovernorMode.LIVE and invariants_violated:
proposed = "stop_safe"
reasons.append({"rule": "invariants_violation", "violations": invariants_violated})

pressure = self.gate_pressure(world.tick)
in_cooldown = self._update_cooldown(world.tick, pressure)
reasons.append({"rule": "gate_pressure", "pressure": round(pressure, 3), "cooldown":
in_cooldown})

withdrawal_recommended = pressure >= self.gate_pressure_cfg.withdrawal_threshold and
self._pressure_sustained_ticks >= 6
if withdrawal_recommended:
reasons.append({"rule": "withdrawal_recommended", "note": "sustained gate
pressure"})

if risk.knowledge_hole:
reasons.append({"rule": "knowledge_hole", "epistemic": round(risk.epistemic, 3)})

if self.mode == GovernorMode.LIVE and risk.band in self.policy.human_gate_bands_live:
allow_new = (not in_cooldown) or (risk.band == "STOP")
if allow_new and not self._active_gates("action"):
expires = 3 if risk.band == "STOP" else 5
self._new_gate(risk.band, world.tick, proposed, "action",
related_id=f"action:{world.tick}", stage=1, expires_in_ticks=expires)
reasons.append({"rule": "action_gate_created", "band": risk.band})
elif not allow_new and risk.band != "STOP":
reasons.append({"rule": "action_gate_suppressed", "reason": "cooldown"})

g = self._select_current_gate("action")
requires_gate = g is not None

gate_id = g.gate_id if g else None

if self.mode == GovernorMode.SHADOW:
action = "none"
reasons.append({"rule": "shadow_mode", "note": "no actuation; proposals only"})
else:
action = "hold_for_approval" if requires_gate else proposed

return Decision(
tick=world.tick,
action=action,
proposed_action=proposed,
band=risk.band,
epistemic=risk.epistemic,
knowledge_hole=risk.knowledge_hole,
requires_human_gate=requires_gate,
human_gate_id=gate_id,
invariants_violated=invariants_violated,
invariant_proofs=[asdict(p) for p in invariant_proofs],
gate_pressure=float(pressure),
withdrawal_recommended=withdrawal_recommended,
in_cooldown=in_cooldown,
reason_chain=reasons,
)

def apply_gate(self, gate_id: str, approved: bool, tick: int, operator_id: Optional[str] = None,
note: str = "") -> Dict[str, Any]:
g = self._gates.get(gate_id)
if g is None or g.approved is not None:
return {"override_applied": False, "error": "no_matching_gate", "gate_id": gate_id}
g.approved = approved
g.operator_id = operator_id
g.note = note
g.resolved_at = self.clock.ts(tick=tick, local_seq=2)
return {"override_applied": True, "gate": asdict(g)}

def get_pending_gates(self, purpose: Optional[str] = None) -> List[HumanGateState]:
return self._active_gates(purpose)

def to_state(self) -> Dict[str, Any]:
return {
"_next_gate_id": self._next_gate_id,
"_gates": {gid: asdict(g) for gid, g in self._gates.items()},
"_gate_events": list(self._gate_events),
"_cooldown_until_tick": self._cooldown_until_tick,
"_pressure_sustained_ticks": self._pressure_sustained_ticks,
"mode": self.mode,
}

def load_state(self, state: Dict[str, Any]) -> None:
self._next_gate_id = int(state.get("_next_gate_id", 1))

self._gates = {gid: HumanGateState(**gd) for gid, gd in (state.get("_gates") or {}).items()}
self._gate_events = list(state.get("_gate_events", []))
self._cooldown_until_tick = int(state.get("_cooldown_until_tick", 0))
self._pressure_sustained_ticks = int(state.get("_pressure_sustained_ticks", 0))
self.mode = str(state.get("mode", self.mode))

#
=============================================================================
# Monitor rules (safe DSL)
#
=============================================================================

@dataclass
class MonitorViolation:
tick: int
asset_key: str
rule_id: str
severity: str
message: str
evidence_hash: str

class MonitorRule(Protocol):
def __call__(self, history: List["MemoryFrame"], current: "MemoryFrame") ->
Optional[MonitorViolation]: ...

@dataclass
class TemporalRule:

rule_id: str
severity: str
description: str
fn: MonitorRule
source_hash: str = ""

class MonitorEngine:
def __init__(self) -> None:
self.rules: List[TemporalRule] = []
self.violations: List[MonitorViolation] = []
self.rule_stats: Dict[str, Dict[str, Any]] = {}

def add_rule(self, rule: TemporalRule) -> None:
self.rules = [r for r in self.rules if r.rule_id != rule.rule_id] + [rule]
self.rule_stats.setdefault(rule.rule_id, {"count": 0, "last_tick": None, "source_hash":
rule.source_hash})

def eval(self, history: List["MemoryFrame"], current: "MemoryFrame") ->
List[MonitorViolation]:
new: List[MonitorViolation] = []
for r in sorted(self.rules, key=lambda x: x.rule_id):
v = r.fn(history, current)
if v is not None:
new.append(v)
self.violations.append(v)
stt = self.rule_stats.setdefault(r.rule_id, {"count": 0, "last_tick": None, "source_hash":
r.source_hash})

stt["count"] = int(stt.get("count", 0)) + 1
stt["last_tick"] = current.tick
return new

def tail(self, n: int = 25, asset_key: Optional[str] = None) -> List[MonitorViolation]:
if asset_key is None:
return self.violations[-n:]
return [v for v in self.violations if v.asset_key == asset_key][-n:]

def to_state(self) -> Dict[str, Any]:
return {"violations": [asdict(v) for v in self.violations], "rule_stats": self.rule_stats}

def load_state(self, state: Dict[str, Any]) -> None:
self.violations = [MonitorViolation(**v) for v in state.get("violations", [])]
self.rule_stats = dict(state.get("rule_stats", {}))

def active_rule_manifest_hash(self) -> str:
manifest = [{"rule_id": r.rule_id, "source_hash": r.source_hash} for r in sorted(self.rules,
key=lambda x: x.rule_id)]
return sha256_json({"manifest": manifest})

def compile_rule_from_dsl(dsl: Dict[str, Any]) -> TemporalRule:
kind = str(dsl.get("kind", "")).strip()
rule_id = str(dsl.get("rule_id", "")).strip()
severity = str(dsl.get("severity", "high")).strip()
desc = str(dsl.get("description", kind)).strip()

source_hash = sha256_json(dsl)

if not rule_id:
raise ValueError("DSL missing rule_id")

if kind == "KH_BLOCKS_ACTIONS":
mode_required = str(dsl.get("mode", GovernorMode.LIVE))
blocked_actions = list(dsl.get("blocked_actions", ["normal", "cautious"]))

def fn(history: List["MemoryFrame"], cur: "MemoryFrame") -> Optional[MonitorViolation]:
if cur.mode != mode_required: return None
if not cur.knowledge_hole: return None
if cur.action in blocked_actions:
msg = f"Knowledge hole blocks action={cur.action} in mode={mode_required}."
return MonitorViolation(cur.tick, cur.asset_key, rule_id, severity, msg,
sha256_json({"frame_hash": cur.hash, "dsl": dsl}))
return None

return TemporalRule(rule_id, severity, desc, fn, source_hash)

if kind == "INV_VIOLATION_FORCES_ACTIONS":
mode_required = str(dsl.get("mode", GovernorMode.LIVE))
allowed_actions = list(dsl.get("allowed_actions", ["stop_safe", "hold_for_approval"]))

def fn(history: List["MemoryFrame"], cur: "MemoryFrame") -> Optional[MonitorViolation]:
if cur.mode != mode_required: return None

violated = any((not p.get("satisfied", True)) for p in cur.invariant_proofs)
if not violated: return None
if cur.action not in allowed_actions:
msg = f"Invariant violation requires action in {allowed_actions}, got {cur.action}."
return MonitorViolation(cur.tick, cur.asset_key, rule_id, severity, msg,
sha256_json({"frame_hash": cur.hash, "dsl": dsl}))
return None

return TemporalRule(rule_id, severity, desc, fn, source_hash)

if kind == "SUSTAINED_FIELD_REQUIRES_FLAG":
field_name = str(dsl.get("field"))
comparator = str(dsl.get("comparator", ">="))
threshold = float(dsl.get("threshold", 0.0))
window = int(dsl.get("window", 3))
require_flag = str(dsl.get("require_flag", "withdrawal_recommended"))

def cmp(v: float) -> bool:
if comparator == ">=": return v >= threshold
if comparator == ">": return v > threshold
if comparator == "<=": return v <= threshold
if comparator == "<": return v < threshold
raise ValueError("Bad comparator")

def fn(history: List["MemoryFrame"], cur: "MemoryFrame") -> Optional[MonitorViolation]:
frames = (history + [cur])[-window:]

if len(frames) < window: return None
vals = []
for f in frames:
if field_name == "gate_pressure": vals.append(float(f.gate_pressure))
elif field_name == "epistemic": vals.append(float(f.epistemic))
elif field_name == "risk": vals.append(float(f.risk))
else: return None
if all(cmp(v) for v in vals):
if getattr(cur, require_flag, None) is not True:
msg = f"Sustained {field_name}{comparator}{threshold} for {window} ticks requires
{require_flag}=True."
return MonitorViolation(cur.tick, cur.asset_key, rule_id, severity, msg,
sha256_json({"frame_hash": cur.hash, "dsl": dsl, "vals": vals}))
return None

return TemporalRule(rule_id, severity, desc, fn, source_hash)

raise ValueError(f"Unsupported DSL kind: {kind}")

#
=============================================================================
# Memory (integrity-only hashing)
#
=============================================================================

@dataclass
class MemoryFrame:

id: int
asset_key: str
timestamp: str
tick: int
mode: str
scenario: str
summary: str
risk_band: str
risk: float
epistemic: float
knowledge_hole: bool
action: str
proposed_action: str
predicted_risk: float
winner_agent: str
human_gate_pending: bool
human_gate_id: Optional[str]
gate_pressure: float
withdrawal_recommended: bool
in_cooldown: bool
world_snapshot: Dict[str, Any]
invariant_proofs: List[Dict[str, Any]]
policy_id: str
policy_hash: str
rule_manifest_hash: str
determinism_sig: str

hash: str
prev_hash: str
# observability:
tick_ms: float = 0.0

class MemoryEngine:
def __init__(self, clock: DeterministicClock) -> None:
self.clock = clock
self.frames: List[MemoryFrame] = []
self._last_hash: str = "0" * 64
self._next_id: int = 1

def add_frame(
self,
*,
asset_key: str,
tick: int,
mode: str,
scenario: str,
risk: RiskPacket,
decision: Decision,
predicted_risk: float,
winner_agent: str,
tick_ms: float, # observability only
world_snapshot: Dict[str, Any],
policy_id: str,

policy_hash: str,
rule_manifest_hash: str,
determinism_sig: str,
) -> MemoryFrame:
ts = self.clock.ts(tick=tick, local_seq=self._next_id)

summary = (
f"{asset_key} tick {tick} mode={mode} band={risk.band} risk={risk.risk:.3f} "
f"ep={risk.epistemic:.2f} kh={risk.knowledge_hole} action={decision.action} "
f"gate={decision.requires_human_gate} gp={decision.gate_pressure:.2f}
cd={decision.in_cooldown}"
)

frame_integrity = {
"id": self._next_id,
"asset_key": asset_key,
"timestamp": ts,
"tick": tick,
"mode": mode,
"scenario": scenario,
"summary": summary,
"risk_band": risk.band,
"risk": risk.risk,
"epistemic": risk.epistemic,
"knowledge_hole": risk.knowledge_hole,
"action": decision.action,

"proposed_action": decision.proposed_action,
"predicted_risk": predicted_risk,
"winner_agent": winner_agent,
"human_gate_pending": decision.requires_human_gate,
"human_gate_id": decision.human_gate_id,
"gate_pressure": decision.gate_pressure,
"withdrawal_recommended": decision.withdrawal_recommended,
"in_cooldown": decision.in_cooldown,
"world_snapshot": world_snapshot,
"invariant_proofs": decision.invariant_proofs,
"policy_id": policy_id,
"policy_hash": policy_hash,
"rule_manifest_hash": rule_manifest_hash,
"determinism_sig": determinism_sig,
"prev_hash": self._last_hash,
}

h = sha256_json(frame_integrity)

frame = MemoryFrame(
id=self._next_id,
asset_key=asset_key,
timestamp=ts,
tick=tick,
mode=mode,
scenario=scenario,

summary=summary,
risk_band=risk.band,
risk=risk.risk,
epistemic=risk.epistemic,
knowledge_hole=risk.knowledge_hole,
action=decision.action,
proposed_action=decision.proposed_action,
predicted_risk=predicted_risk,
winner_agent=winner_agent,
human_gate_pending=decision.requires_human_gate,
human_gate_id=decision.human_gate_id,
gate_pressure=decision.gate_pressure,
withdrawal_recommended=decision.withdrawal_recommended,
in_cooldown=decision.in_cooldown,
world_snapshot=world_snapshot,
invariant_proofs=decision.invariant_proofs,
policy_id=policy_id,
policy_hash=policy_hash,
rule_manifest_hash=rule_manifest_hash,
determinism_sig=determinism_sig,
prev_hash=self._last_hash,
hash=h,
tick_ms=float(tick_ms), # stored but excluded from hash
)

self.frames.append(frame)

self._last_hash = h
self._next_id += 1
return frame

def tail(self, n: int = 16, asset_key: Optional[str] = None) -> List[MemoryFrame]:
if asset_key is None:
return self.frames[-n:]
return [f for f in self.frames if f.asset_key == asset_key][-n:]

def verify_chain(self) -> Tuple[bool, Optional[int]]:
prev = "0" * 64
for idx, f in enumerate(self.frames):
frame_integrity = {
"id": f.id,
"asset_key": f.asset_key,
"timestamp": f.timestamp,
"tick": f.tick,
"mode": f.mode,
"scenario": f.scenario,
"summary": f.summary,
"risk_band": f.risk_band,
"risk": f.risk,
"epistemic": f.epistemic,
"knowledge_hole": f.knowledge_hole,
"action": f.action,
"proposed_action": f.proposed_action,

"predicted_risk": f.predicted_risk,
"winner_agent": f.winner_agent,
"human_gate_pending": f.human_gate_pending,
"human_gate_id": f.human_gate_id,
"gate_pressure": f.gate_pressure,
"withdrawal_recommended": f.withdrawal_recommended,
"in_cooldown": f.in_cooldown,
"world_snapshot": f.world_snapshot,
"invariant_proofs": f.invariant_proofs,
"policy_id": f.policy_id,
"policy_hash": f.policy_hash,
"rule_manifest_hash": f.rule_manifest_hash,
"determinism_sig": f.determinism_sig,
"prev_hash": prev,
}
expected = sha256_json(frame_integrity)
if f.prev_hash != prev or f.hash != expected:
return False, idx
prev = f.hash
return True, None

def to_json(self) -> str:
return json.dumps([asdict(f) for f in self.frames], indent=2, sort_keys=True)

def load_from_json(self, frames_json: List[Dict[str, Any]]) -> None:
self.frames = []

self._last_hash = "0" * 64
self._next_id = 1
for fdict in frames_json:
frame = MemoryFrame(**fdict)
self.frames.append(frame)
self._last_hash = frame.hash
self._next_id = max(self._next_id, frame.id + 1)

#
=============================================================================
# Avalon (lightweight scoring)
#
=============================================================================

@dataclass
class OversightItem:
summary: str
risks: List[str]
recommendations: List[str]
confidence: float
tags: List[str]

class Judge:
def score(self, item: OversightItem, disagreement: float) -> Dict[str, float]:
text = item.summary + " " + " ".join(item.recommendations)
words = text.split()
length = len(words)

contains_safety = any(w in text.lower() for w in ["monitor", "pause", "review", "human",
"safety", "limit", "rollback", "halt"])
length_score = clamp(length / 250.0, 0.0, 1.0)
safety_bias = 0.8 if contains_safety else 0.4
clarity = clamp(length_score * 0.4 + safety_bias * 0.6, 0.1, 0.99)
base_risk = (1.0 - clarity) * 100.0
risk_value = clamp(base_risk + disagreement * 0.5, 0.0, 100.0)
overall = int(10 + clarity * 89)
return {"clarity": round(clarity * 100, 1), "risk": round(risk_value, 1), "overall":
float(overall)}

def structured_item(asset_key: str, risk: RiskPacket, decision: Decision, rule_manifest: str) ->
OversightItem:
summary = f"{asset_key} tick={risk.tick} band={risk.band} risk={risk.risk:.3f}
ep={risk.epistemic:.2f} kh={risk.knowledge_hole} action={decision.action}."
risks = [f"band={risk.band}", f"knowledge_hole={risk.knowledge_hole}",
f"sensor_health={risk.features.get('sensor_health',1.0):.2f}",
f"rule_manifest={rule_manifest[:10]}..."]
recs = ["Use counterfactual deltas to target mitigations.", "Treat knowledge holes as
admissibility blockers for model advice."]
return OversightItem(summary=summary, risks=risks, recommendations=recs,
confidence=0.9, tags=["structured", f"band:{risk.band}"])

#
=============================================================================
# Replay capsule + determinism signature
#
=============================================================================

def build_determinism_signature(session_id: str, policy_hash: str, rule_manifest_hash: str,
asset_key: str, asset_seed: int, tick: int) -> str:
return sha256_json({
"kernel": KERNEL_VERSION,
"schema": CAPSULE_SCHEMA_VERSION,
"session_id": session_id,
"policy_hash": policy_hash,
"rule_manifest_hash": rule_manifest_hash,
"asset_key": asset_key,
"asset_seed": asset_seed,
"tick": tick,
})[:24]

#
=============================================================================
# OmegaV6.5 orchestrator
#
=============================================================================

@dataclass
class AssetContext:
asset: AssetId
world: WorldState
seed: int
governor: Governor
risk_state: RiskState = field(default_factory=RiskState)
credit: float = 0.0

last_tick_ms: float = 0.0
last_det_sig: str = ""
last_predicted_risk: float = 0.0

class OmegaV65:
def __init__(self, *, mode: str, policy: RiskPolicy, session_id: str, clock: DeterministicClock) ->
None:
self.mode = mode
self.policy = policy
self.clock = clock
self.audit = AuditSpine(clock, session_id)
self.kernel = SafetyKernel(policy.risk_cfg)
self.memory = MemoryEngine(clock)
self.monitors = MonitorEngine()
self.fault_profile = FaultProfile()
self.assets: Dict[str, AssetContext] = {}
self.last_interactions: Dict[str, InteractionSummary] = {}

builtins = [
{
"kind": "KH_BLOCKS_ACTIONS",
"rule_id": "R1_KH_BLOCKS_NORMAL",
"severity": "critical",
"description": "Knowledge hole blocks normal/cautious in LIVE.",
"mode": GovernorMode.LIVE,
"blocked_actions": ["normal", "cautious"],

},
{
"kind": "INV_VIOLATION_FORCES_ACTIONS",
"rule_id": "R2_INV_FORCES_STOP",
"severity": "critical",
"description": "Invariant violations force stop_safe/hold_for_approval in LIVE.",
"mode": GovernorMode.LIVE,
"allowed_actions": ["stop_safe", "hold_for_approval"],
},
{
"kind": "SUSTAINED_FIELD_REQUIRES_FLAG",
"rule_id": "R3_PRESSURE_WITHDRAW",
"severity": "high",
"description": "Sustained gate pressure requires withdrawal recommendation.",
"field": "gate_pressure",
"comparator": ">=",
"threshold": 1.0,
"window": 5,
"require_flag": "withdrawal_recommended",
},
]
for dsl in builtins:
self.monitors.add_rule(compile_rule_from_dsl(dsl))

self.audit.log(0, "session_init", {
"session_id": session_id,

"kernel": KERNEL_VERSION,
"schema": CAPSULE_SCHEMA_VERSION,
"policy_id": policy.id,
"policy_hash": policy.source_hash,
"mode": mode,
})

def ensure_asset(self, site: str, asset_name: str) -> AssetId:
site = site or "site-1"
asset_name = asset_name or "asset-1"
asset = AssetId(site, asset_name)
key = asset.key()
if key not in self.assets:
seed = derive_asset_seed(self.audit.session_id, key)
world = WorldState(asset=asset, tick=0, mode=self.mode)
gov = Governor(self.policy, self.mode, key, self.clock)
self.assets[key] = AssetContext(asset=asset, world=world, seed=seed, governor=gov)
self.audit.log(0, "asset_registered", {"asset": asdict(asset), "seed": seed})
return asset

def list_assets(self) -> List[str]:
return sorted(self.assets.keys())

def set_mode(self, mode: str) -> None:
self.mode = mode
for ctx in self.assets.values():

ctx.world.mode = mode
ctx.governor.mode = mode
self.audit.log(0, "mode_changed", {"mode": mode})

def snapshot_asset(self, key: str) -> Optional[Dict[str, Any]]:
ctx = self.assets.get(key)
if ctx is None:
return None
return {
"asset": asdict(ctx.asset),
"seed": ctx.seed,
"tick": ctx.world.tick,
"mode": ctx.world.mode,
"world": ctx.world.to_dict(),
"last_tick_ms": ctx.last_tick_ms,
"credit": ctx.credit,
"det_sig": ctx.last_det_sig,
"predicted_risk": ctx.last_predicted_risk,
}

def _update_credit(self, ctx: AssetContext, risk: RiskPacket, decision: Decision) -> None:
delta = 0.0
if risk.band == "LOW" and (not risk.knowledge_hole) and decision.action in ("normal",
"none"):
delta += 0.4
if risk.band == "WATCH":

delta += 0.1
if risk.band in ("HOLD", "STOP") or risk.knowledge_hole:
delta -= 0.9
if decision.gate_pressure >= 1.0:
delta -= 0.3
ctx.credit = clamp(ctx.credit + delta, -50.0, 50.0)

def verify_integrity(self) -> Dict[str, Any]:
audit_ok, audit_idx = self.audit.verify_chain()
mem_ok, mem_idx = self.memory.verify_chain()
return {"audit_ok": audit_ok, "audit_first_bad_index": audit_idx, "memory_ok": mem_ok,
"memory_first_bad_index": mem_idx}

def tick_all(self, scenario: str) -> Dict[str, Dict[str, Any]]:
if not self.assets:
return {}

# dynamics step (stable ordering)
for key in sorted(self.assets.keys()):
ctx = self.assets[key]
ctx.world.tick += 1
ctx.world = simulate_dynamics(ctx.world, ctx.seed, self.fault_profile)

worlds = {k: self.assets[k].world for k in sorted(self.assets.keys())}
interactions = compute_interactions(worlds)
self.last_interactions = interactions

rule_manifest_hash = self.monitors.active_rule_manifest_hash()

results: Dict[str, Dict[str, Any]] = {}

for key in sorted(self.assets.keys()):
ctx = self.assets[key]
start_ns = time.perf_counter_ns()

update_sensors(ctx.world, ctx.seed, self.fault_profile)
sm = compute_sensor_metrics(ctx.world.sensors)

inter = interactions[key]
proximity_norm = clamp(1.0 - inter.nearest_distance / MAX_PROX_DISTANCE, 0.0, 1.0)
rctx = RiskContext(sensor=sm, proximity=proximity_norm,
same_zone_conflict=inter.same_zone_conflict)

risk = self.kernel.eval(ctx.world, rctx, ctx.risk_state, credit=ctx.credit,
epistemic_threshold=self.policy.epistemic_threshold)

evidence_bundle = {"asset_key": key, "tick": ctx.world.tick, "risk_hash":
sha256_json(asdict(risk))}
inv_proofs, inv_viol = evaluate_invariants(self.policy.invariants, ctx.world, risk.epistemic,
evidence_bundle)

decision = ctx.governor.evaluate(risk, ctx.world, inv_proofs, inv_viol)

end_ns = time.perf_counter_ns()
tick_ms = (end_ns - start_ns) / 1_000_000.0
ctx.last_tick_ms = float(tick_ms)

det_sig = build_determinism_signature(
self.audit.session_id,
self.policy.source_hash,
rule_manifest_hash,
key,
ctx.seed,
ctx.world.tick,
)
ctx.last_det_sig = det_sig

item = structured_item(key, risk, decision, rule_manifest_hash)
scores = [Judge().score(item, disagreement=0.0)]
merged = {k: mean(s[k] for s in scores) for k in ["clarity", "risk", "overall"]}
predicted_risk = clamp(float(merged["risk"]), 0.0, 100.0)
ctx.last_predicted_risk = float(predicted_risk)

self._update_credit(ctx, risk, decision)

frame = self.memory.add_frame(
asset_key=key,
tick=ctx.world.tick,
mode=ctx.world.mode,

scenario=scenario,
risk=risk,
decision=decision,
predicted_risk=predicted_risk,
winner_agent="Responder:Structured",
tick_ms=tick_ms,
world_snapshot=ctx.world.to_dict(),
policy_id=self.policy.id,
policy_hash=self.policy.source_hash,
rule_manifest_hash=rule_manifest_hash,
determinism_sig=det_sig,
)

history = self.memory.tail(250, asset_key=key)[:-1]
new_viols = self.monitors.eval(history, frame)
for v in new_viols:
self.audit.log(ctx.world.tick, "monitor_violation", {
"asset_key": v.asset_key,
"tick": v.tick,
"rule_id": v.rule_id,
"severity": v.severity,
"message": v.message,
"evidence_hash": v.evidence_hash,
"frame_hash": frame.hash,
})

self.audit.log(
ctx.world.tick,
"omega_tick",
payload={
"kernel": KERNEL_VERSION,
"asset_key": key,
"tick": ctx.world.tick,
"risk": asdict(risk),
"decision": asdict(decision),
"predicted_risk": float(predicted_risk),
"policy_id": self.policy.id,
"policy_hash": self.policy.source_hash,
"rule_manifest_hash": rule_manifest_hash,
"determinism_sig": det_sig,
"memory_frame_hash": frame.hash,
},
observability={"tick_ms": float(tick_ms)},
)

results[key] = {
"risk": asdict(risk),
"decision": asdict(decision),
"scores": merged,
"predicted_risk": predicted_risk,
"tick_ms": float(tick_ms),
"det_sig": det_sig,

"rule_manifest_hash": rule_manifest_hash,
"new_violations": [asdict(v) for v in new_viols],
}

return results

#
=============================================================================
# Replay capsule + self-test (unchanged structure)
#
=============================================================================

def build_replay_capsule(omega: OmegaV65) -> Dict[str, Any]:
return {
"version": KERNEL_VERSION,
"schema_version": CAPSULE_SCHEMA_VERSION,
"exported_at": omega.clock.ts(tick=0, local_seq=999),
"session": {"session_id": omega.audit.session_id, "mode": omega.mode, "clock":
omega.clock.to_state()},
"policy": {"active_policy": asdict(omega.policy)},
"fault_profile": asdict(omega.fault_profile),
"assets": {
key: {
"asset": asdict(ctx.asset),
"seed": ctx.seed,
"world": ctx.world.to_dict(),
"risk_state": asdict(ctx.risk_state),

"credit": ctx.credit,
"governor": ctx.governor.to_state(),
"last_det_sig": ctx.last_det_sig,
}
for key, ctx in omega.assets.items()
},
"audit": [asdict(e) for e in omega.audit.entries],
"memory": [asdict(f) for f in omega.memory.frames],
"monitors": omega.monitors.to_state(),
"integrity_boundary": {"observability_fields": sorted(list(OBSERVABILITY_FIELDS))},
}

def load_replay_capsule(capsule: Dict[str, Any]) -> OmegaV65:
session_id = str(capsule["session"]["session_id"])
clock = DeterministicClock.from_state(session_id, capsule["session"]["clock"])
policy = build_policy(capsule["policy"]["active_policy"] if
isinstance(capsule["policy"]["active_policy"], dict) else DEFAULT_POLICY_DICT)
omega = OmegaV65(mode=str(capsule["session"]["mode"]), policy=policy,
session_id=session_id, clock=clock)

omega.fault_profile = FaultProfile(**(capsule.get("fault_profile") or {}))

omega.audit.entries = []
omega.audit.seq = 0
omega.audit.prev_hash = omega.audit.genesis_hash
for e in capsule.get("audit", []):
entry = AuditEntry(**e)

omega.audit.entries.append(entry)
omega.audit.seq = max(omega.audit.seq, entry.seq)
omega.audit.prev_hash = entry.hash

omega.memory.load_from_json(capsule.get("memory", []))
omega.monitors.load_state(capsule.get("monitors", {}))

omega.assets = {}
for key, ad in (capsule.get("assets") or {}).items():
asset = AssetId(**ad["asset"])
wd = ad["world"]
world = WorldState(asset=asset, tick=int(wd.get("tick", 0)), mode=omega.mode)
world.pose = Pose(**wd.get("pose", {}))
world.vehicle = VehicleState(**wd.get("vehicle", {}))
sensors_dict = wd.get("sensors", {})
world.sensors = SensorSuite(
drift=[SensorChannel(**c) for c in sensors_dict.get("drift", [])],
speed=[SensorChannel(**c) for c in sensors_dict.get("speed", [])],
stability=[SensorChannel(**c) for c in sensors_dict.get("stability", [])],
)
gov = Governor(omega.policy, omega.mode, key, omega.clock)
gov.load_state(ad.get("governor", {}))
ctx = AssetContext(
asset=asset,
world=world,
seed=int(ad["seed"]),

governor=gov,
risk_state=RiskState(**(ad.get("risk_state") or {})),
credit=float(ad.get("credit", 0.0)),
last_det_sig=str(ad.get("last_det_sig", "")),
)
omega.assets[key] = ctx

return omega

@dataclass
class DeterminismCheckResult:
ok: bool
mismatch: Optional[Dict[str, Any]]

def determinism_self_test(omega: OmegaV65, scenario: str, ticks: int = 10) ->
DeterminismCheckResult:
base = build_replay_capsule(omega)
a = load_replay_capsule(base)
b = load_replay_capsule(base)

for i in range(ticks):
a.tick_all(scenario)
b.tick_all(scenario)

if a.monitors.active_rule_manifest_hash() != b.monitors.active_rule_manifest_hash():
return DeterminismCheckResult(False, {"tick_index": i+1, "reason":
"rule_manifest_mismatch"})

for k in sorted(a.assets.keys()):
if a.assets[k].last_det_sig != b.assets[k].last_det_sig:
return DeterminismCheckResult(False, {"tick_index": i+1, "asset_key": k, "reason":
"det_sig_mismatch"})
a_tail = (a.memory.tail(1, asset_key=k)[0].hash if a.memory.tail(1, asset_key=k) else
None)
b_tail = (b.memory.tail(1, asset_key=k)[0].hash if b.memory.tail(1, asset_key=k) else
None)
if a_tail != b_tail:
return DeterminismCheckResult(False, {"tick_index": i+1, "asset_key": k, "reason":
"memory_tail_hash_mismatch"})

return DeterminismCheckResult(True, None)

#
=============================================================================
# Streamlit UI (same structure as your paste)
#
=============================================================================

st.set_page_config(page_title="OmegaV6.5 – Governance Kernel", layout="wide")

def init_session() -> None:
if "omega" not in st.session_state:
session_id = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
clock = DeterministicClock(session_id)
policy = build_policy(DEFAULT_POLICY_DICT)

st.session_state.omega = OmegaV65(mode=GovernorMode.SHADOW, policy=policy,
session_id=session_id, clock=clock)
st.session_state.det_check_last = None
st.session_state.omega.ensure_asset("site-1", "vehicle-1")

init_session()
omega: OmegaV65 = st.session_state.omega # type: ignore[assignment]

st.sidebar.header("OmegaV6.5 Configuration")

mode = st.sidebar.selectbox("Governor mode (global)", [GovernorMode.SHADOW,
GovernorMode.TRAINING, GovernorMode.LIVE],
index=[GovernorMode.SHADOW, GovernorMode.TRAINING,
GovernorMode.LIVE].index(omega.mode))
if mode != omega.mode:
omega.set_mode(mode)

st.sidebar.markdown("#### Assets")
site_input = st.sidebar.text_input("Site ID", value="site-1")
asset_input = st.sidebar.text_input("Asset ID", value="vehicle-1")
if st.sidebar.button("Ensure asset exists"):
omega.ensure_asset(site_input.strip(), asset_input.strip())

asset_keys = omega.list_assets()
active_asset_key = st.sidebar.selectbox("Active asset", options=asset_keys, index=0)

st.sidebar.markdown("#### Epistemic gating")

ep_th = st.sidebar.slider("Epistemic threshold (knowledge hole)", 0.0, 1.0,
float(omega.policy.epistemic_threshold), 0.01)
if abs(ep_th - float(omega.policy.epistemic_threshold)) > 1e-9:
cfg = dict(DEFAULT_POLICY_DICT)
cfg["epistemic_threshold"] = float(ep_th)
omega.policy = build_policy(cfg)
omega.kernel = SafetyKernel(omega.policy.risk_cfg)
for ctx in omega.assets.values():
ctx.governor.policy = omega.policy
omega.audit.log(0, "policy_updated", {"epistemic_threshold": float(ep_th), "policy_hash":
omega.policy.source_hash})

fault_exp = st.sidebar.expander("Fault injection (simulation only)", expanded=False)
with fault_exp:
fp = omega.fault_profile
fp.drift_spike_prob = st.slider("Drift spike probability", 0.0, 0.5, float(fp.drift_spike_prob),
0.01)
fp.dropout_prob = st.slider("Telemetry dropout probability", 0.0, 0.5, float(fp.dropout_prob),
0.01)
fp.freeze_prob = st.slider("Sensor freeze probability", 0.0, 0.5, float(fp.freeze_prob), 0.01)
fp.negative_speed_prob = st.slider("Negative speed probability", 0.0, 0.5,
float(fp.negative_speed_prob), 0.01)
fp.contradictory_prob = st.slider("Contradictory reading probability", 0.0, 0.5,
float(fp.contradictory_prob), 0.01)
fp.timestamp_anomaly_prob = st.slider("Timestamp anomaly probability", 0.0, 0.5,
float(fp.timestamp_anomaly_prob), 0.01)

st.sidebar.markdown("---")

if st.sidebar.button("Verify integrity chains"):
integrity = omega.verify_integrity()
if integrity["audit_ok"] and integrity["memory_ok"]:
st.sidebar.success("Audit + Memory hash chains verified OK.")
else:
st.sidebar.error(f"Audit OK={integrity['audit_ok']} (bad
idx={integrity['audit_first_bad_index']}), "
f"Memory OK={integrity['memory_ok']} (bad
idx={integrity['memory_first_bad_index']}).")

cap_exp = st.sidebar.expander("Replay Capsule", expanded=False)
with cap_exp:
if st.button("Export replay capsule"):
capsule = build_replay_capsule(omega)
st.download_button("Download omega_v6_5_replay_capsule.json",
data=json.dumps(capsule, indent=2, sort_keys=True),
file_name="omega_v6_5_replay_capsule.json",
mime="application/json")
uploaded = st.file_uploader("Import replay capsule JSON", type=["json"])
if uploaded is not None:
try:
capsule = json.loads(uploaded.read().decode("utf-8"))
st.session_state.omega = load_replay_capsule(capsule)
st.success("Replay capsule imported. Session restored.")
st.experimental_rerun()
except Exception as e:
st.error(f"Failed to import capsule: {e}")

st.title("OmegaV6.5 – Deterministic Governance Kernel")
st.caption("Integrity-deterministic audit/memory + replay capsules • Observability timing
excluded • Non-actuating oversight OS")

scenario = st.text_area("Describe the system / scenario OmegaV6.5 is supervising.", height=110,
placeholder="Example: Haul-truck fleet; GNSS dropouts; convoy spacing
constraints; human-gated ops.")

c1, c2, c3 = st.columns([1, 1, 6])
with c1:
run_tick = st.button("Advance Tick")
with c2:
det_test = st.button("Determinism Self-Test")

if det_test:
if not scenario.strip():
st.warning("Add a scenario description first.")
else:
res = determinism_self_test(omega, scenario.strip(), ticks=10)
st.session_state.det_check_last = asdict(res)
if res.ok:
st.success("Determinism self-test passed (10 ticks).")
else:
st.error("Determinism self-test FAILED.")
st.code(json.dumps(res.mismatch, indent=2), language="json")

tick_results = None
if run_tick and scenario.strip():
tick_results = omega.tick_all(scenario.strip())

snapshot = omega.snapshot_asset(active_asset_key)
if snapshot is None:
st.error("Unknown asset.")
st.stop()

world = snapshot["world"]
vehicle = world["vehicle"]

mcols = st.columns(7)
mcols[0].metric("Asset", active_asset_key)
mcols[1].metric("Tick", snapshot["tick"])
mcols[2].metric("Mode", snapshot["mode"].upper())
mcols[3].metric("Drift (deg)", f"{vehicle['drift_deg']:.1f}")
mcols[4].metric("Stability", f"{vehicle['stability']:.1f}")
mcols[5].metric("tick_ms (obs)", f"{snapshot['last_tick_ms']:.2f}")
mcols[6].metric("Det sig", (snapshot["det_sig"][:10] + "...") if snapshot["det_sig"] else "—")

st.markdown("---")
left, right = st.columns([1.15, 1.35])

with left:
st.subheader("Safety Envelope (last tick)")

last_frame = omega.memory.tail(1, asset_key=active_asset_key)
if last_frame:
f = last_frame[0]
st.write(f.summary)

df_cf = pd.DataFrame([{"Factor": k, "Δrisk if fixed": v} for k, v in (tick_results or
{}).get(active_asset_key, {}).get("risk", {}).get("counterfactual_deltas", {}).items()]) \
if tick_results else pd.DataFrame()
if not df_cf.empty:
st.markdown("**Counterfactual Δ-Risk**")
st.dataframe(df_cf.sort_values("Δrisk if fixed", ascending=False),
use_container_width=True, height=220)

st.markdown("**Invariant Proofs**")
st.dataframe(pd.DataFrame(f.invariant_proofs), use_container_width=True, height=180)

st.markdown("**Integrity**")
st.code(json.dumps({
"memory_hash": f.hash,
"prev_hash": f.prev_hash,
"policy_hash": f.policy_hash,
"rule_manifest_hash": f.rule_manifest_hash,
"det_sig": f.determinism_sig,
}, indent=2), language="json")
else:
st.info("Advance at least one tick to populate memory.")

with right:
st.subheader("Audit + Monitor Tail")
integrity = omega.verify_integrity()
st.write(f"Audit chain OK: **{integrity['audit_ok']}** | Memory chain OK:
**{integrity['memory_ok']}**")

st.markdown("**Recent audit entries**")
tail = omega.audit.tail(12)
adf = pd.DataFrame([{
"seq": e.seq,
"kind": e.kind,
"hash": e.hash[:10] + "...",
"prev": e.prev_hash[:10] + "...",
"obs_tick_ms": e.observability.get("tick_ms", None),
} for e in tail])
st.dataframe(adf, use_container_width=True, height=260)

st.markdown("**Recent monitor violations**")
vtail = omega.monitors.tail(12, asset_key=active_asset_key)
vdf = pd.DataFrame([asdict(v) for v in vtail])
st.dataframe(vdf if not vdf.empty else pd.DataFrame([{"note": "No violations yet."}]),
use_container_width=True, height=200)
