package com.flarefitness.backend.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.flarefitness.backend.exception.GlobalExceptionHandler;
import com.flarefitness.backend.exception.ResourceGoneException;
import com.flarefitness.backend.service.SyncStateService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class SyncStateControllerTest {

    @Mock
    private SyncStateService syncStateService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(new SyncStateController(syncStateService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void retiredManagedReviewsEndpointsReturnGone() throws Exception {
        ResourceGoneException gone = new ResourceGoneException("Tai nguyen dong bo da ngung ho tro.");
        when(syncStateService.getAppState("managed-reviews")).thenThrow(gone);
        when(syncStateService.saveAppState(eq("managed-reviews"), any(), any())).thenThrow(gone);

        mockMvc.perform(get("/api/sync/app/managed-reviews"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("RESOURCE_GONE"));

        mockMvc.perform(put("/api/sync/app/managed-reviews")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"payload\":\"[]\"}"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("RESOURCE_GONE"));
    }
}
