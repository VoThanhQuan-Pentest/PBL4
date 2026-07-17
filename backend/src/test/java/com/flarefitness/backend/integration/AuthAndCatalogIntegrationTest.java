package com.flarefitness.backend.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.UserRepository;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthAndCatalogIntegrationTest extends ContainerizedIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private ProductRepository productRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private String username;
    private String password;
    private String productId;

    @BeforeEach
    void createFixture() {
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        username = "integration_" + suffix;
        password = "Integration#1";

        User user = new User();
        user.setId("integration-user-" + suffix);
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("CUSTOMER");
        user.setHoTen("Integration Customer");
        user.setEmail(username + "@example.test");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);

        Product product = new Product();
        productId = "integration-product-" + suffix;
        product.setId(productId);
        product.setSku("IT-" + suffix);
        product.setTenSanPham("Integration Product");
        product.setDanhMuc("Testing");
        product.setThuongHieu("Flare");
        product.setGiaNhap(new BigDecimal("250000"));
        product.setGiaBan(new BigDecimal("500000"));
        product.setTonKho(77);
        product.setTrangThai("Dang ban");
        product.setGhiChu("internal only");
        product.setHinhAnhUrl("./assets/images/logo PBL3.png.webp");
        product.setDeleted(false);
        product.setCreatedAt(LocalDateTime.now());
        productRepository.save(product);
    }

    @Test
    void loginUsesHttpOnlyCookieAndAuthenticatedEndpointAcceptsIt() throws Exception {
        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();
        String csrfToken = objectMapper.readTree(csrf.getResponse().getContentAsString()).get("token").asText();

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .cookie(new MockCookie("XSRF-TOKEN", csrfToken))
                        .header("X-XSRF-TOKEN", csrfToken)
                        .content(objectMapper.writeValueAsString(java.util.Map.of("username", username, "password", password))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").doesNotExist())
                .andReturn();

        String setCookie = login.getResponse().getHeader("Set-Cookie");
        assertThat(setCookie).contains("access_token=").contains("HttpOnly").contains("SameSite=Strict");
        String accessToken = setCookie.substring(setCookie.indexOf("access_token=") + "access_token=".length(), setCookie.indexOf(';'));

        mockMvc.perform(get("/api/auth/me").cookie(new MockCookie("access_token", accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));
    }

    @Test
    void logoutRevokesOnlyTheCurrentCookieSession() throws Exception {
        MvcResult csrf = mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();
        String csrfToken = objectMapper.readTree(csrf.getResponse().getContentAsString()).get("token").asText();

        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .cookie(new MockCookie("XSRF-TOKEN", csrfToken))
                        .header("X-XSRF-TOKEN", csrfToken)
                        .content(objectMapper.writeValueAsString(java.util.Map.of("username", username, "password", password))))
                .andExpect(status().isOk())
                .andReturn();
        String setCookie = login.getResponse().getHeader("Set-Cookie");
        String accessToken = setCookie.substring(setCookie.indexOf("access_token=") + "access_token=".length(), setCookie.indexOf(';'));

        mockMvc.perform(post("/api/auth/logout")
                        .cookie(new MockCookie("access_token", accessToken), new MockCookie("XSRF-TOKEN", csrfToken))
                        .header("X-XSRF-TOKEN", csrfToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/auth/me").cookie(new MockCookie("access_token", accessToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void publicCatalogRedactsInternalProductFields() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/products/{id}", productId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(productId))
                .andExpect(jsonPath("$.gia_nhap").doesNotExist())
                .andExpect(jsonPath("$.ghi_chu").doesNotExist())
                .andReturn();

        JsonNode payload = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(payload.get("ton_kho").asInt()).isEqualTo(10);
    }
}
