package com.flarefitness.backend.controller;

import com.flarefitness.backend.service.siem.SiemPreventionService;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ServiceUnavailableException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Map;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Internal Docker-network control channel. Never route /internal/ through public Nginx. */
@RestController
@RequestMapping("/internal/v1/prevention")
public class PreventionInternalController {
    private final SiemPreventionService service;
    private final Path tokenFile;

    public PreventionInternalController(SiemPreventionService service,
            @Value("${siem.prevention.service-token-file:/run/flare-secrets/prevention.token}") String tokenFile) {
        this.service = service;
        this.tokenFile = Path.of(tokenFile);
    }

    @GetMapping("/policy")
    public Map<String, Object> policy(@RequestHeader(value = "X-Flare-Service-Token", required = false) String token) {
        checkToken(token);
        return service.activePolicy();
    }

    @PostMapping("/ack")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void acknowledge(@RequestHeader(value = "X-Flare-Service-Token", required = false) String token,
                            @RequestBody Map<String, Object> body) {
        checkToken(token);
        Object version = body.get("version");
        Object checksum = body.get("checksum");
        if (!(version instanceof Number number) || !(checksum instanceof String value)
                || number.longValue() < 0 || value.length() != 64) {
            throw new BadRequestException("Invalid acknowledgement.");
        }
        service.acknowledge(number.longValue(), value);
    }

    private void checkToken(String candidate) {
        byte[] expected;
        try {
            expected = Files.readString(tokenFile, StandardCharsets.UTF_8).trim().getBytes(StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new ServiceUnavailableException("Prevention token unavailable.");
        }
        byte[] actual = String.valueOf(candidate == null ? "" : candidate)
                .getBytes(StandardCharsets.UTF_8);
        if (expected.length < 32 || expected.length > 256
                || !MessageDigest.isEqual(expected, actual)) {
            throw new AccessDeniedException("Invalid service credentials.");
        }
    }
}
