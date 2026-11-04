package com.flarefitness.backend.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.security.CustomUserDetailsService;
import com.flarefitness.backend.security.IpAddressResolver;
import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.security.JwtTokenService;
import com.flarefitness.backend.security.RedisTokenStore;
import com.flarefitness.backend.service.siem.SecurityEventService;
import com.flarefitness.backend.controller.support.SupportController;
import com.flarefitness.backend.service.support.SupportChatService;
import com.flarefitness.backend.dto.support.SupportThreadResponse;
import com.flarefitness.backend.security.IpRateLimitService;
import org.springframework.mock.web.MockCookie;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/** Actual security filter chain and MVC; no Boot/database/Redis/model/application startup. */
class ApiSecurityHeadersTest {
    private static AnnotationConfigWebApplicationContext context;
    private static MockMvc mvc;

    @BeforeAll static void startOwnedContext() {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("owned-headers",
                Map.of("app.security.auth-cookie-secure", "false")));
        context.register(Fixture.class, SecurityConfig.class);
        context.refresh();
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @AfterAll static void closeOwnedContext() { if (context != null) context.close(); }
    @AfterEach void clearAuthentication() { SecurityContextHolder.clearContext(); }

    @Test void publicJsonHasOnePolicyAndRetainsDefaultCacheProtection() throws Exception {
        assertHeaders(mvc.perform(get("/api/health")).andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("owned")).andReturn());
    }

    @Test void authenticatedJsonStillSucceeds() throws Exception {
        assertHeaders(mvc.perform(get("/api/auth/me").with(user("owned-user").roles("CUSTOMER")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("owned")).andReturn());
    }

    @Test void authenticationFailureKeepsItsJsonErrorContract() throws Exception {
        assertHeaders(mvc.perform(get("/api/auth/me")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED")).andReturn());
    }

    @Test void csrfFailureKeepsItsJsonErrorContract() throws Exception {
        assertHeaders(mvc.perform(post("/api/auth/login")).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("CSRF_INVALID")).andReturn());
    }

    @Test void supportInitializationRequiresUnsafeMethodAuthenticationAndCsrf() throws Exception {
        SupportChatService support = context.getBean(SupportChatService.class);
        mvc.perform(get("/api/support/me").param("createIfMissing", "true")
                        .with(user("owned-customer").roles("CUSTOMER")))
                .andExpect(status().isNoContent());
        mvc.perform(head("/api/support/me").param("createIfMissing", "true")
                        .with(user("owned-customer").roles("CUSTOMER")))
                .andExpect(status().isNoContent());
        verify(support, never()).initializeCurrentCustomerThread(any());

        mvc.perform(post("/api/support/me").with(user("owned-customer").roles("CUSTOMER")))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("CSRF_INVALID"));
        mvc.perform(post("/api/support/me").with(user("owned-customer").roles("CUSTOMER"))
                        .cookie(new MockCookie("XSRF-TOKEN", "owned-proof")).header("X-XSRF-TOKEN", "wrong-proof"))
                .andExpect(status().isForbidden());
        verify(support, never()).initializeCurrentCustomerThread(any());

        when(support.initializeCurrentCustomerThread(any())).thenReturn(new SupportThreadResponse(
                "owned-thread", "owned-customer", null, "open", null, null, List.of()));
        mvc.perform(post("/api/support/me").with(user("owned-customer").roles("CUSTOMER"))
                        .cookie(new MockCookie("XSRF-TOKEN", "owned-proof")).header("X-XSRF-TOKEN", "owned-proof"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value("owned-thread"));
        verify(support).initializeCurrentCustomerThread(any());
        mvc.perform(post("/api/support/me").cookie(new MockCookie("XSRF-TOKEN", "owned-proof"))
                        .header("X-XSRF-TOKEN", "owned-proof"))
                .andExpect(status().isUnauthorized());
        assertThat(com.flarefitness.backend.service.siem.EndpointCategory.fromHandlerPattern(
                "POST", "/api/support/me")).isEqualTo(com.flarefitness.backend.service.siem.EndpointCategory.SUPPORT_READ);
    }

    private void assertHeaders(MvcResult result) {
        var response = result.getResponse();
        assertThat(response.getHeaders("Content-Security-Policy")).hasSize(1);
        assertThat(response.getHeader("Content-Security-Policy")).contains("default-src 'none'",
                "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'");
        assertThat(response.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeader("X-Frame-Options")).isEqualTo("DENY");
        assertThat(response.getHeader("Cache-Control")).contains("no-store");
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity @EnableWebMvc
    static class Fixture {
        @Bean UserDetailsService users() {
            return name -> { throw new UsernameNotFoundException("Owned fixture only"); };
        }
        @Bean JwtAuthenticationFilter jwtFilter() {
            return new JwtAuthenticationFilter(new JwtTokenService("owned-header-fixture-key-".repeat(3), 3600),
                    mock(RedisTokenStore.class), new CustomUserDetailsService(null), "owned-auth");
        }
        @Bean SecurityErrorResponseWriter errors() {
            return new SecurityErrorResponseWriter(new ObjectMapper().findAndRegisterModules());
        }
        @Bean SecurityEventService events() { return mock(SecurityEventService.class); }
        @Bean com.flarefitness.backend.repository.UserRepository actorUsers() {
            return mock(com.flarefitness.backend.repository.UserRepository.class);
        }
        @Bean IpAddressResolver addresses() { return new IpAddressResolver(""); }
        @Bean OwnedApi api() { return new OwnedApi(); }
        @Bean SupportChatService supportService() { return mock(SupportChatService.class); }
        @Bean SupportController supportApi(SupportChatService supportService, IpAddressResolver addresses) {
            return new SupportController(supportService, addresses, mock(IpRateLimitService.class), 20);
        }
    }

    @RestController
    static class OwnedApi {
        @GetMapping({"/api/health", "/api/auth/me"})
        Map<String, String> response() { return Map.of("status", "owned"); }
    }
}
