package com.flarefitness.backend.dto.common;

import java.util.List;

public record CursorPageResponse<T>(
        List<T> content,
        String nextBefore,
        String nextBeforeId,
        boolean hasMore
) {
}
