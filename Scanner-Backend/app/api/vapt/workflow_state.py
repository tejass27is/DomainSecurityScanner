from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

State = Literal[
    "pending",
    "requested",
    "rejected",
    "confirmed",
    "queued",
    "in_progress",
    "completed",
    "closed",
    "reopened",
    "cancelled",
]

Action = Literal[
    "submit_request",
    "soc_approve",
    "client_accept_new_date",
    "client_reject_new_date",
    "soc_propose_new_date",
    "scan_finish",
    "soc_close_cycle",
    "soc_reopen_cycle",
    "reminder_sent",
    "remediation_approved",
    "remediation_rejected",
]


@dataclass
class ScheduleContext:
    state: State
    retry_count: int = 0
    max_retry_count: int = 3
    confirmation_sent: bool = False
    reminder_sent: bool = False
    cycle_status: str = "open"
    next_due_at: Optional[str] = None
    note: Optional[str] = None


def reconcile_schedule_flow(
    context: ScheduleContext,
    action: Action,
    *,
    proposed_date: Optional[str] = None,
) -> ScheduleContext:
    """Reconcile the VAPT reschedule lifecycle across the complete review loop.

    This is the canonical state-machine translation for the business rules:
    - initial request starts in requested
    - SOC/client approval funnel into a shared confirmed state
    - rejected dates can loop back to rescheduling until a retry cap is hit
    - remediation reopening requires explicit SOC review before a new revalidation request
    - verification closure and reopen transitions remain explicit SOC-controlled decisions
    """
    state = context.state
    retry_count = context.retry_count
    max_retry_count = context.max_retry_count

    if action == "submit_request":
        if state in ("pending", "cancelled", "rejected"):
            context.state = "requested"
            context.note = "Awaiting SOC schedule review"
        return context

    if action == "soc_propose_new_date":
        if state in ("requested", "rejected"):
            context.state = "requested"
            context.note = proposed_date or "New date proposed by SOC"
        return context

    if action == "client_accept_new_date":
        if state in ("requested", "rejected"):
            context.state = "confirmed"
            context.confirmation_sent = False
            context.note = "Client accepted the revised date"
        return context

    if action == "client_reject_new_date":
        if state in ("requested", "rejected"):
            retry_count += 1
            context.retry_count = retry_count
            if retry_count >= max_retry_count:
                context.state = "cancelled"
                context.cycle_status = "cancelled"
                context.note = "Date rejected; escalation required"
            else:
                context.state = "rejected"
                context.note = "Client rejected proposed date; user may reschedule"
        return context

    if action == "soc_approve":
        if state in ("requested", "rejected"):
            context.state = "confirmed"
            context.confirmation_sent = False
            context.note = "Approved by SOC"
        return context

    if action == "reminder_sent":
        if context.state == "confirmed":
            context.reminder_sent = True
            context.note = "Reminder sent to client"
        return context

    if action == "scan_finish":
        if context.state == "confirmed":
            context.state = "completed"
            context.note = "Verification scan completed"
        return context

    if action == "remediation_approved":
        if context.state in ("reopened", "completed"):
            context.state = "confirmed"
            context.note = "SOC approved remediation before re-verification"
        return context

    if action == "remediation_rejected":
        if context.state in ("reopened", "completed"):
            context.state = "reopened"
            context.note = "SOC rejected remediation; client must fix the remaining findings"
        return context

    if action == "soc_close_cycle":
        if context.state in ("completed", "confirmed"):
            context.state = "closed"
            context.cycle_status = "closed"
            context.note = "VAPT cycle closed by SOC"
        return context

    if action == "soc_reopen_cycle":
        if context.state in ("completed", "closed"):
            context.state = "reopened"
            context.cycle_status = "reopened"
            context.note = "SOC reopened remediation"
        return context

    return context
