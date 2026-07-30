package com.airwallex.ap2.protocol;

public enum CheckoutStatus {
    incomplete,
    requires_escalation,
    ready_for_complete,
    complete_in_progress,
    completed,
    canceled
}