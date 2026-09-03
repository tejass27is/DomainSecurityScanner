from app.api.vapt.workflow_state import ScheduleContext, reconcile_schedule_flow


def test_rejection_can_loop_back_to_reschedule_without_terminal_dead_end():
    ctx = ScheduleContext(state="rejected", retry_count=1, max_retry_count=3)

    result = reconcile_schedule_flow(ctx, "submit_request")

    assert result.state == "requested"
    assert result.note == "Awaiting SOC schedule review"


def test_reopen_requires_soc_review_before_new_revalidation_request():
    ctx = ScheduleContext(state="reopened")

    result = reconcile_schedule_flow(ctx, "remediation_approved")

    assert result.state == "confirmed"
    assert result.note == "SOC approved remediation before re-verification"


def test_confirmed_state_is_shared_for_client_and_soc_approvals():
    ctx = ScheduleContext(state="requested")
    approved = reconcile_schedule_flow(ctx, "soc_approve")

    assert approved.state == "confirmed"
    assert approved.note == "Approved by SOC"

    requeued = ScheduleContext(state="requested")
    accepted = reconcile_schedule_flow(requeued, "client_accept_new_date")

    assert accepted.state == "confirmed"
    assert accepted.note == "Client accepted the revised date"


def test_soc_proposes_new_date_then_client_accepts_and_cycle_closes():
    requested = ScheduleContext(state="requested")
    proposed = reconcile_schedule_flow(requested, "soc_propose_new_date", proposed_date="2026-09-10T15:00:00Z")

    assert proposed.state == "requested"
    assert proposed.note == "2026-09-10T15:00:00Z"

    accepted = reconcile_schedule_flow(proposed, "client_accept_new_date")
    assert accepted.state == "confirmed"

    closed = reconcile_schedule_flow(accepted, "scan_finish")
    assert closed.state == "completed"

    final = reconcile_schedule_flow(closed, "soc_close_cycle")
    assert final.state == "closed"
    assert final.cycle_status == "closed"


def test_client_reject_then_soc_approve_keeps_loop_open_for_rework():
    rejected = ScheduleContext(state="requested")
    rejected_after_client = reconcile_schedule_flow(rejected, "client_reject_new_date")

    assert rejected_after_client.state == "rejected"
    assert rejected_after_client.retry_count == 1

    approved = reconcile_schedule_flow(rejected_after_client, "soc_approve")
    assert approved.state == "confirmed"
    assert approved.note == "Approved by SOC"
