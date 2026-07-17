package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.auth.AuthMessageResponse;
import com.flarefitness.backend.dto.auth.CurrentUserResponse;
import com.flarefitness.backend.dto.profile.ChangePasswordRequest;
import com.flarefitness.backend.dto.profile.ProfileEmailOtpRequest;
import com.flarefitness.backend.dto.profile.UpdateProfileRequest;
import com.flarefitness.backend.service.ProfileService;
import com.flarefitness.backend.security.IpAddressResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final ProfileService profileService;
    private final IpAddressResolver ipAddressResolver;

    public ProfileController(ProfileService profileService, IpAddressResolver ipAddressResolver) {
        this.profileService = profileService;
        this.ipAddressResolver = ipAddressResolver;
    }

    @GetMapping
    public ResponseEntity<CurrentUserResponse> getProfile(Authentication authentication) {
        return ResponseEntity.ok(profileService.getProfile(authentication.getName()));
    }

    @PutMapping
    public ResponseEntity<CurrentUserResponse> updateProfile(
            Authentication authentication,
            @Valid @RequestBody UpdateProfileRequest request
    ) {
        return ResponseEntity.ok(profileService.updateProfile(authentication.getName(), request));
    }

    @PostMapping("/email/otp")
    public ResponseEntity<AuthMessageResponse> sendProfileEmailOtp(
            Authentication authentication,
            @Valid @RequestBody ProfileEmailOtpRequest request,
            HttpServletRequest httpServletRequest
    ) {
        profileService.sendProfileEmailOtp(
                authentication.getName(), request.email(), ipAddressResolver.resolve(httpServletRequest));
        return ResponseEntity.ok(new AuthMessageResponse("Ma OTP xac nhan email moi da duoc gui."));
    }

    @PutMapping("/password")
    public ResponseEntity<Void> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        profileService.changePassword(authentication.getName(), request);
        return ResponseEntity.noContent().build();
    }
}
