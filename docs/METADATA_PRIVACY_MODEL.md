# Metadata Privacy Model

This document describes what metadata is hidden, what may still leak, and the roadmap for improving traffic-analysis resistance.

## Hidden by Design

- Message plaintext and cryptographic key material.
- Sender identity from server perspective for sealed sender paths.
- Exact plaintext length via bucket-based message padding.

## Potentially Exposed / Not Hidden

- Recipient routing metadata required for delivery.
- Communication timing/frequency patterns.
- Group membership and social-graph inferences at service layer.
- Network-level metadata (IP, transport-level observations) outside this library.

## Current Mitigations

- Sealed sender envelope flow for sender metadata minimization.
- Fixed-size bucket padding to reduce size-based traffic analysis.
- Replay and downgrade detection to reduce active manipulation impact.

## Privacy Non-Goals

- Global network anonymity.
- Complete resistance to timing correlation attacks.
- Protection against a fully compromised endpoint device.

## Roadmap

1. Expand padding strategy analysis with production telemetry-safe measurements.
2. Evaluate optional timing obfuscation strategies at application transport layer.
3. Add explicit group metadata minimization guidance for host applications.
4. Reassess metadata leakage findings after third-party audit milestones.
