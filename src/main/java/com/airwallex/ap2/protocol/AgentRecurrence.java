package com.airwallex.ap2.protocol;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AgentRecurrence(String type, Frequency frequency, Integer maxOccurrences) {
    public static final String TYPE = "payment.agent_recurrence";
    public AgentRecurrence { if (type == null) type = TYPE; }
    public AgentRecurrence(Frequency frequency, Integer maxOccurrences) { this(TYPE, frequency, maxOccurrences); }
}