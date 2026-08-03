package com.airwallex.ap2.mandate;

public interface Mandate<T> {
    String serialized();
    T mandatePayload();
    default boolean isValid() { return true; }
}