package com.flarefitness.backend.service.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.support.SupportMessageResponse;
import com.flarefitness.backend.dto.support.SupportThreadResponse;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.support.SupportMessage;
import com.flarefitness.backend.entity.support.SupportThread;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.support.SupportMessageRepository;
import com.flarefitness.backend.repository.support.SupportThreadRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class SupportChatServiceTest {

    @Mock
    private SupportThreadRepository threadRepository;
    @Mock
    private SupportMessageRepository messageRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private CustomerRepository customerRepository;

    private SupportChatService service;
    private User customer;
    private Authentication customerAuthentication;
    private Authentication staffAuthentication;

    @BeforeEach
    void setUp() {
        service = new SupportChatService(threadRepository, messageRepository, userRepository, customerRepository);
        customer = user("customer-1", "customer", "customer");
        customerAuthentication = authentication(customer);
        staffAuthentication = authentication(user("staff-1", "staff", "staff"));
    }

    @Test
    void workspaceUsesPageAndBatchedLookupsWithBoundedMessages() {
        SupportThread thread = thread("thread-1", customer.getId());
        Customer customerProfile = new Customer();
        customerProfile.setId("profile-1");
        customerProfile.setUserId(customer.getId());
        customerProfile.setTenKhach("Customer Name");
        customerProfile.setDeleted(false);
        SupportMessage message = message("message-1", thread.getId(), "customer", "Need help");

        when(threadRepository.findAllByOrderByUpdatedAtDesc(any(Pageable.class)))
                .thenAnswer(invocation -> {
                    Pageable pageable = invocation.getArgument(0);
                    return new PageImpl<>(List.of(thread), pageable, 1);
                });
        when(userRepository.findAllById(anyCollection())).thenReturn(List.of(customer));
        when(customerRepository.findActiveByUserIdIn(anyCollection())).thenReturn(List.of(customerProfile));
        when(messageRepository.findRecentByThreadIdIn(anyCollection(), anyInt())).thenReturn(List.of(message));

        PageResponse<SupportThreadResponse> response = service.getThreadsForWorkspacePage(staffAuthentication, 0, 500);

        assertThat(response.size()).isEqualTo(100);
        assertThat(response.content()).singleElement().satisfies(item -> {
            assertThat(item.id()).isEqualTo(thread.getId());
            assertThat(item.messages()).singleElement().satisfies(saved -> {
                assertThat(saved.id()).isEqualTo(message.getId());
                assertThat(saved.text()).isEqualTo("Need help");
            });
        });
        verify(customerRepository, never()).findAll();
        verify(messageRepository).findRecentByThreadIdIn(anyCollection(), anyInt());
    }

    @Test
    void firstCustomerThreadCreationLocksTheCustomerBeforeSaving() {
        when(threadRepository.findFirstByCustomerUserId(customer.getId()))
                .thenReturn(Optional.empty(), Optional.empty());
        when(userRepository.findActiveByIdForUpdate(customer.getId())).thenReturn(Optional.of(customer));
        when(threadRepository.save(any(SupportThread.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(messageRepository.findTop50ByThreadIdOrderByCreatedAtDesc(any())).thenReturn(List.of());

        SupportThreadResponse response = service.getCurrentCustomerThread(customerAuthentication, true);

        assertThat(response).isNotNull();
        assertThat(response.accountKey()).isEqualTo(customer.getId());
        verify(userRepository).findActiveByIdForUpdate(customer.getId());
        verify(threadRepository).save(any(SupportThread.class));
        verify(messageRepository).save(any(SupportMessage.class));
    }

    @Test
    void messageHistoryIsServedThroughBoundedPage() {
        SupportThread thread = thread("thread-1", customer.getId());
        SupportMessage message = message("message-1", thread.getId(), "staff", "We can help");
        when(threadRepository.findFirstByCustomerUserId(customer.getId())).thenReturn(Optional.of(thread));
        when(messageRepository.findByThreadIdOrderByCreatedAtDesc(any(), any(PageRequest.class)))
                .thenReturn(new PageImpl<>(List.of(message), PageRequest.of(0, 20), 81));

        PageResponse<SupportMessageResponse> response = service.getCurrentCustomerMessages(customerAuthentication, 0, 20);

        assertThat(response.totalElements()).isEqualTo(81);
        assertThat(response.hasNext()).isTrue();
        assertThat(response.content()).singleElement().satisfies(saved -> {
            assertThat(saved.id()).isEqualTo("message-1");
            assertThat(saved.sender()).isEqualTo("staff");
        });
    }

    private User user(String id, String username, String role) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setRole(role);
        user.setHoTen(username + " name");
        user.setStatus("ACTIVE");
        user.setDeleted(false);
        return user;
    }

    private Authentication authentication(User user) {
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    private SupportThread thread(String id, String customerUserId) {
        SupportThread thread = new SupportThread();
        thread.setId(id);
        thread.setCustomerUserId(customerUserId);
        thread.setStatus("Đang mở");
        thread.setCreatedAt(LocalDateTime.of(2026, 1, 1, 10, 0));
        thread.setUpdatedAt(LocalDateTime.of(2026, 1, 1, 10, 0));
        return thread;
    }

    private SupportMessage message(String id, String threadId, String sender, String text) {
        SupportMessage message = new SupportMessage();
        message.setId(id);
        message.setThreadId(threadId);
        message.setSenderType(sender);
        message.setText(text);
        message.setCreatedAt(LocalDateTime.of(2026, 1, 1, 10, 0));
        return message;
    }
}
