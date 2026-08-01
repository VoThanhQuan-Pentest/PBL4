package com.flarefitness.backend.dto.review;

import java.time.LocalDateTime;

public record PublicProductReviewResponse(
        String id,
        String productId,
        String reviewer,
        Integer rating,
        String content,
        LocalDateTime createdAt
) {
}
