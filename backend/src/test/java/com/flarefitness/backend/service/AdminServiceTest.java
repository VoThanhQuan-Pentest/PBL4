package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.security.RedisTokenStore;
import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private CustomerRepository customerRepository;
    @Mock private OrderRepository orderRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private PhoneNumberService phoneNumberService;
    @Mock private RedisTokenStore redisTokenStore;
    @Mock private AuditLogService auditLogService;

    private AdminService adminService;

    @BeforeEach
    void setUp() {
        adminService = new AdminService(
                userRepository,
                customerRepository,
                orderRepository,
                passwordEncoder,
                phoneNumberService,
                redisTokenStore,
                auditLogService);
    }

    @Test
    void usersPageClampsSizeAndLoadsCustomersOnlyForThePage() {
        User user = user();
        Customer customer = new Customer();
        customer.setId("customer-1");
        customer.setUserId(user.getId());
        customer.setSdt("0900000000");

        when(userRepository.findAllByOrderByHoTenAsc(org.mockito.ArgumentMatchers.any(Pageable.class)))
                .thenAnswer(invocation -> {
                    Pageable pageable = invocation.getArgument(0);
                    return new PageImpl<>(List.of(user), pageable, 101);
                });
        when(customerRepository.findActiveByUserIdIn(List.of(user.getId()))).thenReturn(List.of(customer));

        var response = adminService.getUsersPage(-5, 999);

        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        verify(userRepository).findAllByOrderByHoTenAsc(pageable.capture());
        assertThat(pageable.getValue().getPageNumber()).isZero();
        assertThat(pageable.getValue().getPageSize()).isEqualTo(100);
        assertThat(response.content()).hasSize(1);
        assertThat(response.content().get(0).sdt()).isEqualTo("0900000000");
        assertThat(response.hasNext()).isTrue();
    }

    private User user() {
        User user = new User();
        user.setId("user-1");
        user.setUsername("admin-page-test");
        user.setPassword("encoded");
        user.setRole("Khach hang");
        user.setHoTen("Page Test");
        user.setEmail("page@example.test");
        user.setStatus("Hoat dong");
        user.setDeleted(false);
        user.setCreatedAt(LocalDateTime.now());
        return user;
    }
}
