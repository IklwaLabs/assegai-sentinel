# The Detection Engine

Sentinel is a monitoring tool first and a threat detector second. This document explains what
that ordering means, what exists today, and what is designed to exist next.

## Status: not yet implemented

There is no detection engine in v0.1. No rule runs, no risk score is produced, and no alert
fires. The `riskScore` field on a connection is `null` for this reason.

The interface reflects that honestly: the connection detail panel says "Not yet assessed" rather
than showing a zero, which would read as "safe" — a claim Sentinel has not earned. Nothing in
the navigation is a disabled placeholder pretending the feature exists.

This document describes the design that is committed to, so that the first rule is written
against a shape rather than improvised.

## The two rules that will not change

**1. Every finding must be able to explain itself in one sentence.**

A person deciding whether to act on a finding needs to know what the system observed and why it
mattered, without reading documentation. So a finding is not a score; it is an observation plus
a reason:

```text
BAD
  "127 connections to this host on 24 ports in 40 seconds, none of which are
   common services. That pattern is what a port scan looks like."

GOOD
  "Unusual score"
  "risk: 72"
  "anomaly"
```

The second form is not merely unhelpful, it is actively harmful: a number with no explanation
either gets ignored or gets over-trusted, and both outcomes are bad. A finding that cannot state
its own reason in one sentence is not finished.

**2. Detection is local and offline.**

No reputation service, no cloud lookup, no model download, no blocklist fetch. A rule may load
a blocklist the user provides from a file; it may not fetch one. A network monitor that phones
home to decide whether your traffic is suspicious has already shown that it cannot be trusted
with the traffic.

This is not only a privacy position. It means a user in an air-gapped environment gets the same
detection as everyone else, and that an adversary cannot poison the verdicts by feeding the
detector.

## The intended shape

```rust
pub trait Rule: Send + Sync {
    /// Stable identifier, recorded with every finding.
    fn id(&self) -> &'static str;

    /// One-line, human-readable description of what this rule looks for.
    fn description(&self) -> &'static str;

    /// Inspects a flow, given the context it appeared in.
    ///
    /// Returning `None` means "nothing to report", which is the common case and must be cheap.
    fn evaluate(&self, flow: &Flow, context: &RuleContext) -> Option<Finding>;
}
```

`RuleContext` exists because most interesting signals are not visible in a single flow: beaconing
is a timing regularity, DNS tunnelling is a name-length distribution, a scan is a *set* of
destinations. So context carries what a flow alone cannot: recent flows, per-host connection
counts, timing history, and the local address set.

A rule is a pure function of that input. It does not write to the database, does not emit
directly, and does not block. It returns a `Finding`, and the engine decides what happens to it.
That is what makes a rule testable against a fixture and replayable from a capture file.

### Findings

A finding carries:

- the rule that produced it
- the flow or entity it concerns
- a severity, from a fixed small set
- the one-sentence explanation
- the observations that produced it, so the explanation is checkable rather than asserted
- a timestamp

Severity is a **label on a category the user understands** — critical, high, medium, low — not a
floating-point score. A score invites the question "how high is high enough", which has no good
answer. A category is a statement about urgency, and urgency is a judgement a human makes.

Where a score is genuinely useful for *ranking* within a category, it may be present as a
secondary sort key. It is never the headline.

## Planned rules, in the order they will be built

Ordered by how much they depend on the rest of the system, not by severity.

**1. Port scan detection.** Many distinct destination ports to one host in a short window, few
of them common services. Needs: per-host connection history, timing. The clearest signal in the
set, and the best first rule to validate the design.

**2. Unusual outbound volume.** A flow transferring substantially more than this machine's
observed baseline for that destination. Needs: traffic history per endpoint, a baseline model.
Careful: this is the rule most likely to produce false positives on a machine that has never seen
a large download, and it must be tuned or it will train the user to ignore it.

**3. DNS tunnelling.** Excessively long subdomains, high volume of unique names under one
domain, unusually high entropy in labels. Needs: DNS query parsing and per-domain aggregation.

**4. Beaconing.** Regular intervals between connections to the same host. Needs: timing history
per endpoint. Effective against command-and-control, and prone to false positives against
anything that polls — mail clients, chat applications, telemetry. Needs an interval tolerance
and a minimum connection count.

**5. Plaintext credentials.** Known protocols carrying credentials without TLS. Needs: payload
inspection, which is the first feature that would retain payload bytes — and the reason
`capturePayloadSamples` exists as an explicit, default-off setting.

**6. Known-malicious destination match.** Only against a list the user supplies. Not against a
fetched list, per the offline rule above.

**7. New or unusual process for a destination.** Needs process attribution, which is not built
yet and is the largest single piece of remaining platform work.

## How rules will be evaluated

- **Inside the engine**, on the task that already owns the flow table. Not in a frontend, and
  not on a separate thread that would need a lock on the same state.
- **After aggregation**, on a flow's current state rather than per packet. A rule that inspected
  every packet would be a performance problem and, for most of these signals, would not work:
  a scan is only visible as a set.
- **Throttled per flow**, so a rule that fires on every packet of a long connection does not
  produce a thousand identical findings.
- **Deterministically**, so a capture file replayed twice produces the same findings. No
  wall-clock dependence in a rule's decision, no randomness.

## Testing rules

A rule is a pure function, so a rule test is a table: given flows and context, assert the
findings. No capture driver, no privileges, no network.

Every rule needs at least:

- a **positive** case that must fire, from a generated fixture
- a **negative** case that must not fire, because a rule that only has positive tests will fire
  on everything
- a **boundary** case at the threshold
- a **benign pattern that resembles it**, because that is the case that decides whether the rule
  is usable

That last one matters more than it sounds. A port-scan rule that also fires on a browser opening
many connections is worse than no rule, because it trains the user to dismiss findings. Each
planned rule above names its likely false-positive source for this reason.

## What Sentinel will not do

- **Block traffic.** Sentinel is a monitor. Injecting or dropping packets to enforce a policy is
  a different product with different risks, and doing it here would change what a capture
  captures.
- **Send data anywhere.** See [SECURITY.md](../SECURITY.md).
- **Score without explaining.** Covered above.
- **Learn from your traffic in the background.** A model trained silently on a user's traffic,
  with no way to inspect or delete it, is surveillance with a nice interface. Baselines are
  computed, shown, and resettable.
- **Claim a verdict from a single observation.** A finding is an observation worth your attention,
  not a conclusion. The wording reflects that.