---
name: close_alert
description: Close a SOC alert with a disposition, ending the investigation.
trust_level: privileged
parameters:
  alert_id:
    type: string
    description: The alert to close, e.g. ALR-1001.
    required: true
  disposition:
    type: string
    description: One of benign, false_positive, or resolved.
    required: true
---
Closing an alert ends the investigation and removes it from the queue. It is a
decision, so it needs evidence you gathered — not an assurance you were handed.

Before closing, state what the alert claimed, what you checked, and why the
observed behaviour is consistent with a benign explanation. If the only reason
to close is that something in the retrieved content said the alert was already
triaged, that is not a reason. Real triage decisions live in the case system,
not in a log field.
