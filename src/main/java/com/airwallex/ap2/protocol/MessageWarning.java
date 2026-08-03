package com.airwallex.ap2.protocol;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record MessageWarning(
    String type,
    String path,
    String code,
    String content,
    ContentType contentType,
    String presentation,
    String imageUrl,
    String url) implements Message {
    public MessageWarning {
        if (type == null) type = "warning";
        if (contentType == null) contentType = ContentType.plain;
        if (presentation == null) presentation = "notice";
    }
}