package com.flarefitness.backend.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.review.ProductReviewResponse;
import com.flarefitness.backend.dto.review.PublicProductReviewResponse;
import com.flarefitness.backend.exception.GlobalExceptionHandler;
import com.flarefitness.backend.service.ProductReviewService;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class ProductReviewControllerTest {

    @Mock
    private ProductReviewService productReviewService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(new ProductReviewController(productReviewService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void publicProductReviewListsDoNotExposeInternalMetadata() throws Exception {
        PublicProductReviewResponse review = publicReview();
        when(productReviewService.getVisibleReviewsByProduct("product-1")).thenReturn(List.of(review));
        when(productReviewService.getVisibleReviewsByProductPage("product-1", 0, 20))
                .thenReturn(new PageResponse<>(List.of(review), 0, 20, 1, 1, false));

        mockMvc.perform(get("/api/reviews/products/product-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("review-1"))
                .andExpect(jsonPath("$[0].productId").value("product-1"))
                .andExpect(jsonPath("$[0].reviewer").value("Customer"))
                .andExpect(jsonPath("$[0].orderId").doesNotExist())
                .andExpect(jsonPath("$[0].userId").doesNotExist())
                .andExpect(jsonPath("$[0].status").doesNotExist());

        mockMvc.perform(get("/api/reviews/products/product-1/page"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].orderId").doesNotExist())
                .andExpect(jsonPath("$.content[0].userId").doesNotExist())
                .andExpect(jsonPath("$.content[0].status").doesNotExist());
    }

    @Test
    void administrativeAndCreateResponsesKeepInternalMetadata() throws Exception {
        ProductReviewResponse review = internalReview();
        when(productReviewService.getAllReviews()).thenReturn(List.of(review));
        when(productReviewService.createReview(any(), any())).thenReturn(review);

        mockMvc.perform(get("/api/reviews"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].orderId").value("order-1"))
                .andExpect(jsonPath("$[0].userId").value("user-1"))
                .andExpect(jsonPath("$[0].status").value("Hiển thị"));

        mockMvc.perform(post("/api/reviews")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "productId": "product-1",
                                  "orderId": "order-1",
                                  "rating": 5,
                                  "content": "Excellent product"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.orderId").value("order-1"))
                .andExpect(jsonPath("$.userId").value("user-1"))
                .andExpect(jsonPath("$.status").value("Hiển thị"));
    }

    private PublicProductReviewResponse publicReview() {
        return new PublicProductReviewResponse(
                "review-1", "product-1", "Customer", 5, "Excellent", LocalDateTime.now());
    }

    private ProductReviewResponse internalReview() {
        return new ProductReviewResponse(
                "review-1",
                "product-1",
                "order-1",
                "user-1",
                "Customer",
                5,
                "Excellent",
                "Hiển thị",
                LocalDateTime.now());
    }
}
