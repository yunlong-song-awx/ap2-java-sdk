package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = MessageError.class, name = "error"),
    @JsonSubTypes.Type(value = MessageWarning.class, name = "warning"),
    @JsonSubTypes.Type(value = MessageInfo.class, name = "info")
})
public sealed interface Message permits MessageError, MessageWarning, MessageInfo {
}