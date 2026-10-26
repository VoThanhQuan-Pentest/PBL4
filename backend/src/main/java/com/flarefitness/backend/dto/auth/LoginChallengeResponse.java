package com.flarefitness.backend.dto.auth;

public record LoginChallengeResponse(String challengeId, long expiresIn, String emailMasked, String channel) { }
