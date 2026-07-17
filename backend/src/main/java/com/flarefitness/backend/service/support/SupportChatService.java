package com.flarefitness.backend.service.support;

import com.flarefitness.backend.dto.support.SupportCustomerResponse;
import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.support.SupportMessageRequest;
import com.flarefitness.backend.dto.support.SupportMessageResponse;
import com.flarefitness.backend.dto.support.SupportThreadResponse;
import com.flarefitness.backend.dto.support.SupportThreadStatusRequest;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.entity.support.SupportMessage;
import com.flarefitness.backend.entity.support.SupportThread;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.UserRepository;
import com.flarefitness.backend.repository.support.SupportMessageRepository;
import com.flarefitness.backend.repository.support.SupportThreadRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.text.Normalizer;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SupportChatService {

    private static final String CANONICAL_STATUS_OPEN = "\u0110ang m\u1edf";
    private static final String CANONICAL_STATUS_PROCESSING = "\u0110ang x\u1eed l\u00fd";
    private static final String CANONICAL_STATUS_CLOSED = "\u0110\u00e3 \u0111\u00f3ng";
    private static final Set<String> ALLOWED_STATUSES = Set.of(
            CANONICAL_STATUS_OPEN,
            CANONICAL_STATUS_PROCESSING,
            CANONICAL_STATUS_CLOSED
    );
    private static final LocalTime WORK_START = LocalTime.of(8, 0);
    private static final LocalTime WORK_END = LocalTime.of(21, 0);
    private static final int DEFAULT_WORKSPACE_PAGE_SIZE = 50;
    private static final int MAX_WORKSPACE_PAGE_SIZE = 100;
    private static final int THREAD_MESSAGE_SUMMARY_LIMIT = 50;
    private static final int MAX_MESSAGE_PAGE_SIZE = 100;

    private final SupportThreadRepository supportThreadRepository;
    private final SupportMessageRepository supportMessageRepository;
    private final UserRepository userRepository;
    private final CustomerRepository customerRepository;

    public SupportChatService(
            SupportThreadRepository supportThreadRepository,
            SupportMessageRepository supportMessageRepository,
            UserRepository userRepository,
            CustomerRepository customerRepository
    ) {
        this.supportThreadRepository = supportThreadRepository;
        this.supportMessageRepository = supportMessageRepository;
        this.userRepository = userRepository;
        this.customerRepository = customerRepository;
    }

    @Transactional
    public SupportThreadResponse getCurrentCustomerThread(Authentication authentication, boolean createIfMissing) {
        User user = requireAuthenticatedUser(authentication);
        assertCustomerUser(user);

        SupportThread thread = findOrCreateThread(user, createIfMissing);
        if (thread == null) {
            return null;
        }

        return toThreadResponse(thread, customerRepository.findUniqueActiveByUserId(user.getId()).orElse(null), user);
    }

    @Transactional
    public SupportThreadResponse appendCustomerMessage(Authentication authentication, SupportMessageRequest request) {
        User user = requireAuthenticatedUser(authentication);
        assertCustomerUser(user);

        SupportThread thread = findOrCreateThread(user, true);
        LocalDateTime now = LocalDateTime.now();
        saveMessage(thread.getId(), "customer", user.getId(), request.text(), now);

        String autoReply = resolveAutoReply(request.text(), now);
        LocalDateTime updatedAt = now;
        if (!autoReply.isBlank()) {
            updatedAt = now.plusSeconds(1);
            saveMessage(thread.getId(), "staff", "", autoReply, updatedAt);
        }

        thread.setUpdatedAt(updatedAt);
        supportThreadRepository.save(thread);
        return toThreadResponse(thread, customerRepository.findUniqueActiveByUserId(user.getId()).orElse(null), user);
    }

    @Transactional(readOnly = true)
    public List<SupportThreadResponse> getThreadsForWorkspace(Authentication authentication) {
        return getThreadsForWorkspacePage(authentication, 0, DEFAULT_WORKSPACE_PAGE_SIZE).content();
    }

    @Transactional(readOnly = true)
    public PageResponse<SupportThreadResponse> getThreadsForWorkspacePage(
            Authentication authentication,
            Integer page,
            Integer size) {
        User currentUser = requireAuthenticatedUser(authentication);
        assertWorkspaceUser(currentUser);

        Page<SupportThread> threadPage = supportThreadRepository.findAllByOrderByUpdatedAtDesc(
                PageRequest.of(normalizePage(page), normalizeWorkspacePageSize(size)));
        List<SupportThreadResponse> threads = toWorkspaceThreadResponses(threadPage.getContent());
        return new PageResponse<>(
                threads,
                threadPage.getNumber(),
                threadPage.getSize(),
                threadPage.getTotalElements(),
                threadPage.getTotalPages(),
                threadPage.hasNext());
    }

    @Transactional(readOnly = true)
    public PageResponse<SupportMessageResponse> getCurrentCustomerMessages(
            Authentication authentication,
            Integer page,
            Integer size) {
        User user = requireAuthenticatedUser(authentication);
        assertCustomerUser(user);
        SupportThread thread = supportThreadRepository.findFirstByCustomerUserId(user.getId()).orElse(null);
        if (thread == null) {
            return new PageResponse<>(List.of(), normalizePage(page), normalizeMessagePageSize(size), 0, 0, false);
        }
        return getMessagePage(thread.getId(), page, size);
    }

    @Transactional(readOnly = true)
    public PageResponse<SupportMessageResponse> getWorkspaceMessages(
            Authentication authentication,
            String threadId,
            Integer page,
            Integer size) {
        User currentUser = requireAuthenticatedUser(authentication);
        assertWorkspaceUser(currentUser);
        if (!supportThreadRepository.existsById(threadId)) {
            throw new ResourceNotFoundException("Khong tim thay cuoc tro chuyen ho tro.");
        }
        return getMessagePage(threadId, page, size);
    }

    private List<SupportThreadResponse> toWorkspaceThreadResponses(List<SupportThread> threads) {
        if (threads == null || threads.isEmpty()) {
            return List.of();
        }

        Set<String> customerUserIds = threads.stream()
                .map(SupportThread::getCustomerUserId)
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.toSet());
        Map<String, User> usersById = userRepository.findAllById(
                customerUserIds
        ).stream().collect(Collectors.toMap(User::getId, user -> user, (left, right) -> left, LinkedHashMap::new));
        Map<String, Customer> customersByUserId = customerRepository.findActiveByUserIdIn(customerUserIds).stream()
                .filter(customer -> customer.getUserId() != null && !customer.getUserId().isBlank())
                .collect(Collectors.toMap(Customer::getUserId, customer -> customer, (left, right) -> left, LinkedHashMap::new));
        Map<String, List<SupportMessage>> messagesByThreadId = supportMessageRepository
                .findRecentByThreadIdIn(threads.stream().map(SupportThread::getId).toList(), THREAD_MESSAGE_SUMMARY_LIMIT)
                .stream()
                .collect(Collectors.groupingBy(SupportMessage::getThreadId, LinkedHashMap::new, Collectors.toList()));

        return threads.stream()
                .map(thread -> toThreadResponse(
                        thread,
                        customersByUserId.get(thread.getCustomerUserId()),
                        usersById.get(thread.getCustomerUserId()),
                        messagesByThreadId.getOrDefault(thread.getId(), List.of())))
                .toList();
    }

    @Transactional
    public SupportThreadResponse appendWorkspaceMessage(Authentication authentication, String threadId, SupportMessageRequest request) {
        User currentUser = requireAuthenticatedUser(authentication);
        assertWorkspaceUser(currentUser);

        SupportThread thread = supportThreadRepository.findById(threadId)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay cuoc tro chuyen ho tro."));
        LocalDateTime now = LocalDateTime.now();
        saveMessage(thread.getId(), "staff", currentUser.getId(), request.text(), now);
        thread.setUpdatedAt(now);
        supportThreadRepository.save(thread);

        User customerUser = userRepository.findById(thread.getCustomerUserId()).orElse(null);
        Customer customer = customerRepository.findUniqueActiveByUserId(thread.getCustomerUserId()).orElse(null);
        return toThreadResponse(thread, customer, customerUser);
    }

    @Transactional
    public SupportThreadResponse updateThreadStatus(Authentication authentication, String threadId, SupportThreadStatusRequest request) {
        User currentUser = requireAuthenticatedUser(authentication);
        assertWorkspaceUser(currentUser);

        String normalizedStatus = resolveStatus(request.status());
        if (normalizedStatus == null) {
            throw new BadRequestException("Trang thai ho tro khong hop le.");
        }

        SupportThread thread = supportThreadRepository.findById(threadId)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay cuoc tro chuyen ho tro."));
        thread.setStatus(normalizedStatus);
        thread.setUpdatedAt(LocalDateTime.now());
        supportThreadRepository.save(thread);

        User customerUser = userRepository.findById(thread.getCustomerUserId()).orElse(null);
        Customer customer = customerRepository.findUniqueActiveByUserId(thread.getCustomerUserId()).orElse(null);
        return toThreadResponse(thread, customer, customerUser);
    }

    /**
     * Serializes first-thread creation on the immutable user row. The matching unique constraint is
     * declared on SupportThread and must be installed by the database migration, while this lock
     * also protects deployments before that migration is applied.
     */
    private SupportThread findOrCreateThread(User user, boolean createIfMissing) {
        SupportThread existing = supportThreadRepository.findFirstByCustomerUserId(user.getId()).orElse(null);
        if (existing != null || !createIfMissing) {
            return existing;
        }

        User lockedUser = userRepository.findActiveByIdForUpdate(user.getId())
                .orElseThrow(() -> new UnauthorizedException("Tai khoan khong con hoat dong."));
        return supportThreadRepository.findFirstByCustomerUserId(lockedUser.getId())
                .orElseGet(() -> createThread(lockedUser));
    }

    private PageResponse<SupportMessageResponse> getMessagePage(String threadId, Integer page, Integer size) {
        Page<SupportMessage> messagePage = supportMessageRepository.findByThreadIdOrderByCreatedAtDesc(
                threadId,
                PageRequest.of(normalizePage(page), normalizeMessagePageSize(size)));
        return PageResponse.from(messagePage.map(this::toMessageResponse));
    }

    private SupportThread createThread(User user) {
        LocalDateTime now = LocalDateTime.now().minusSeconds(1);

        SupportThread thread = new SupportThread();
        thread.setId("support-" + UUID.randomUUID());
        thread.setCustomerUserId(user.getId());
        thread.setStatus(CANONICAL_STATUS_OPEN);
        thread.setCreatedAt(now);
        thread.setUpdatedAt(now);
        supportThreadRepository.save(thread);

        saveMessage(
                thread.getId(),
                "staff",
                "",
                "Xin chào, Flare Fitness đã sẵn sàng hỗ trợ bạn. Hãy gửi nội dung cần tư vấn.",
                now
        );
        return thread;
    }

    private void saveMessage(String threadId, String senderType, String senderUserId, String text, LocalDateTime createdAt) {
        SupportMessage message = new SupportMessage();
        message.setId("message-" + UUID.randomUUID());
        message.setThreadId(threadId);
        message.setSenderType(senderType);
        message.setSenderUserId(senderUserId == null ? "" : senderUserId);
        message.setText(normalizeOutgoingSupportText(text));
        message.setCreatedAt(createdAt);
        supportMessageRepository.save(message);
    }

    private String resolveAutoReply(String text, LocalDateTime now) {
        if (!isBusinessHours(now.toLocalTime())) {
            return "Xin lỗi, hiện đã ngoài giờ làm việc của Flare Fitness (08:00 - 21:00 hằng ngày). Tin nhắn của bạn đã được ghi nhận và nhân viên sẽ phản hồi trong giờ làm việc gần nhất.";
        }

        String normalized = normalizeSupportText(text);
        if (normalized.matches(".*\\b(xin chao|chao|hello|hi|alo)\\b.*")) {
            return "Xin chào, Flare Fitness đã nhận được tin nhắn của bạn. Nhân viên tư vấn sẽ hỗ trợ bạn trong cuộc trò chuyện này.";
        }

        return "";
    }

    private String normalizeOutgoingSupportText(String text) {
        String value = String.valueOf(text == null ? "" : text).trim();
        if (value.contains("Flare Fitness") && value.contains("08:00")) {
            return "Xin l\u1ed7i, hi\u1ec7n \u0111\u00e3 ngo\u00e0i gi\u1edd l\u00e0m vi\u1ec7c c\u1ee7a Flare Fitness (08:00 - 21:00 h\u1eb1ng ng\u00e0y). Tin nh\u1eafn c\u1ee7a b\u1ea1n \u0111\u00e3 \u0111\u01b0\u1ee3c ghi nh\u1eadn v\u00e0 nh\u00e2n vi\u00ean s\u1ebd ph\u1ea3n h\u1ed3i trong gi\u1edd l\u00e0m vi\u1ec7c g\u1ea7n nh\u1ea5t.";
        }
        if (value.contains("Flare Fitness")) {
            return "Xin ch\u00e0o, Flare Fitness \u0111\u00e3 s\u1eb5n s\u00e0ng h\u1ed7 tr\u1ee3 b\u1ea1n. H\u00e3y g\u1eedi n\u1ed9i dung c\u1ea7n t\u01b0 v\u1ea5n.";
        }
        return value;
    }

    private boolean isBusinessHours(LocalTime now) {
        return !now.isBefore(WORK_START) && !now.isAfter(WORK_END);
    }

    private String normalizeSupportText(String value) {
        return Normalizer.normalize(String.valueOf(value == null ? "" : value), Normalizer.Form.NFD)
                .toLowerCase(Locale.ROOT)
                .replace('\u0111', 'd')
                .replace('\u0110', 'd')
                .replaceAll("\\p{M}+", "")
                .replaceAll("[^\\p{L}\\p{N}\\s]", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private String resolveStatus(String status) {
        String normalized = normalizeSupportText(status);
        if (normalized.isBlank()) {
            return null;
        }
        if (normalized.equals("dang mo") || normalized.equals("open")) {
            return CANONICAL_STATUS_OPEN;
        }
        if (normalized.equals("dang xu ly") || normalized.equals("dang xu li") || normalized.equals("processing")) {
            return CANONICAL_STATUS_PROCESSING;
        }
        if (normalized.equals("da dong") || normalized.equals("closed")) {
            return CANONICAL_STATUS_CLOSED;
        }

        String trimmed = String.valueOf(status == null ? "" : status).trim();
        return ALLOWED_STATUSES.contains(trimmed) ? trimmed : null;
    }

    private SupportThreadResponse toThreadResponse(SupportThread thread, Customer customer, User user) {
        return toThreadResponse(
                thread,
                customer,
                user,
                supportMessageRepository.findTop50ByThreadIdOrderByCreatedAtDesc(thread.getId()).stream()
                        .sorted(Comparator.comparing(
                                SupportMessage::getCreatedAt,
                                Comparator.nullsLast(Comparator.naturalOrder()))
                                .thenComparing(SupportMessage::getId, Comparator.nullsLast(Comparator.naturalOrder())))
                        .toList());
    }

    private SupportThreadResponse toThreadResponse(
            SupportThread thread,
            Customer customer,
            User user,
            List<SupportMessage> threadMessages) {
        List<SupportMessageResponse> messages = threadMessages.stream()
                .map(this::toMessageResponse)
                .toList();

        SupportCustomerResponse customerResponse = new SupportCustomerResponse(
                user != null ? user.getId() : thread.getCustomerUserId(),
                customer != null && customer.getTenKhach() != null && !customer.getTenKhach().isBlank()
                        ? customer.getTenKhach()
                        : (user != null ? user.getHoTen() : ""),
                user != null ? user.getUsername() : "",
                customer != null && customer.getEmail() != null && !customer.getEmail().isBlank()
                        ? customer.getEmail()
                        : (user != null ? user.getEmail() : ""),
                customer != null ? customer.getSdt() : ""
        );

        return new SupportThreadResponse(
                thread.getId(),
                thread.getCustomerUserId(),
                customerResponse,
                thread.getStatus(),
                thread.getCreatedAt(),
                thread.getUpdatedAt(),
                messages
        );
    }

    private SupportMessageResponse toMessageResponse(SupportMessage message) {
        return new SupportMessageResponse(
                message.getId(),
                message.getSenderType(),
                message.getText(),
                message.getCreatedAt());
    }

    private int normalizePage(Integer page) {
        return Math.max(page == null ? 0 : page, 0);
    }

    private int normalizeWorkspacePageSize(Integer size) {
        return Math.min(Math.max(size == null ? DEFAULT_WORKSPACE_PAGE_SIZE : size, 1), MAX_WORKSPACE_PAGE_SIZE);
    }

    private int normalizeMessagePageSize(Integer size) {
        return Math.min(Math.max(size == null ? THREAD_MESSAGE_SUMMARY_LIMIT : size, 1), MAX_MESSAGE_PAGE_SIZE);
    }

    private User requireAuthenticatedUser(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new UnauthorizedException("Ban can dang nhap de su dung tinh nang ho tro.");
        }

        return principal.getUser();
    }

    private void assertCustomerUser(User user) {
        if (CurrentUserPrincipal.toAuthority(user.getRole()).equals("ROLE_ADMIN")
                || CurrentUserPrincipal.toAuthority(user.getRole()).equals("ROLE_STAFF")) {
            throw new UnauthorizedException("Tai khoan nhan vien va quan tri vien khong su dung kenh ho tro khach hang.");
        }
    }

    private void assertWorkspaceUser(User user) {
        String authority = CurrentUserPrincipal.toAuthority(user.getRole());
        if (!authority.equals("ROLE_ADMIN") && !authority.equals("ROLE_STAFF")) {
            throw new UnauthorizedException("Ban khong co quyen xem ho tro khach hang.");
        }
    }
}
