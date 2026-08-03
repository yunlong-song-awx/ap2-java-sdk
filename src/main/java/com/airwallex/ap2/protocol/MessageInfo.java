package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record MessageInfo(
    String type,
    String path,
    String code,
    ContentType contentType,
    String content) implements Message {
    public MessageInfo {
        if (type == null) type = "info";
        if (contentType == null) contentType = ContentType.plain;
    }
}