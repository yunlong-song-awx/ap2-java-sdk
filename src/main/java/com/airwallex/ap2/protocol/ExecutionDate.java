package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ExecutionDate(String type, String notBefore, String notAfter) {
    public static final String TYPE = "payment.execution_date";
    public ExecutionDate { if (type == null) type = TYPE; }
    public ExecutionDate(String notBefore, String notAfter) { this(TYPE, notBefore, notAfter); }
}