package com.flarefitness.backend.controller;

import com.flarefitness.backend.exception.ServiceUnavailableException;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Never component-scanned or shipped: explicitly imported by the isolated capture test only. */
@TestComponent
@RestController
public class OwnedLabControlledFaultController {
    @GetMapping("/api/owned-lab/controlled-faults")
    public void controlledFault() {
        throw new ServiceUnavailableException("Controlled owned local test service unavailable.");
    }
}
