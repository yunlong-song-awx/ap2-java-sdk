package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record MessageError(
    String type,
    String code,
    String path,
    ContentType contentType,
    String content,
    Severity severity) implements Message {
    public MessageError {
        if (type == null) type = "error";
        if (contentType == null) contentType = ContentType.plain;
    }
}