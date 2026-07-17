package com.flarefitness.backend.config;

import com.flarefitness.backend.security.JwtAuthenticationFilter;
import com.flarefitness.backend.security.BcryptSha256PasswordEncoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;
    private final SecurityErrorResponseWriter securityErrorResponseWriter;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            UserDetailsService userDetailsService,
            SecurityErrorResponseWriter securityErrorResponseWriter
    ) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
        this.securityErrorResponseWriter = securityErrorResponseWriter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            @org.springframework.beans.factory.annotation.Value("${app.security.auth-cookie-secure}") boolean cookieSecure
    ) throws Exception {
        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepository.setCookieCustomizer(cookie -> cookie.path("/").sameSite("Strict").secure(cookieSecure));
        CsrfTokenRequestAttributeHandler csrfRequestHandler = new CsrfTokenRequestAttributeHandler();
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfRepository)
                        .csrfTokenRequestHandler(csrfRequestHandler))
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) ->
                                securityErrorResponseWriter.write(
                                        response,
                                        HttpStatus.UNAUTHORIZED,
                                        "UNAUTHORIZED",
                                        "Can dang nhap de truy cap tai nguyen nay."))
                        .accessDeniedHandler((request, response, exception) ->
                                securityErrorResponseWriter.write(
                                        response,
                                        HttpStatus.FORBIDDEN,
                                        "FORBIDDEN",
                                        "Ban khong co quyen truy cap tai nguyen nay.")))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/api/health").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.POST,
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/register/otp",
                                "/api/auth/forgot-password",
                                "/api/auth/forgot-password/otp",
                                "/api/auth/forgot-password/otp/verify"
                        ).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/analytics/events").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/products/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/reviews/products/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/analytics/recommendations").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/promo-hunt/campaigns").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/sync/app/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/promo-hunt/campaigns/*/claim").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/reviews").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/reviews", "/api/reviews/page").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers(HttpMethod.PATCH, "/api/reviews/*").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers(HttpMethod.DELETE, "/api/reviews/*").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers("/api/sync/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/orders/me", "/api/orders/me/page").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/orders").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/orders/*/cancel-request").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/orders/*/return-request").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/orders", "/api/orders/page").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers(HttpMethod.PATCH, "/api/orders/*").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers("/api/support/threads/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers("/api/support/me/**").authenticated()
                        .requestMatchers("/api/admin/analytics/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/api/admin/users/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/api/admin/promo-hunt/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/api/admin/vouchers/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers("/api/admin/products/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_STAFF")
                        .requestMatchers("/api/analytics/me/**").authenticated()
                        .requestMatchers("/api/profile/**", "/api/auth/me", "/api/auth/logout", "/api/auth/logout-all").authenticated()
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BcryptSha256PasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
