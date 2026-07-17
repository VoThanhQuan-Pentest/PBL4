package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.order.OrderAddressPayload;
import com.flarefitness.backend.dto.order.OrderItemPayload;
import com.flarefitness.backend.dto.order.OrderRequest;
import com.flarefitness.backend.dto.order.OrderResponse;
import com.flarefitness.backend.dto.order.OrderStatusUpdateRequest;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.Order;
import com.flarefitness.backend.entity.OrderItem;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.ProductVariant;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.OrderItemRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductVariantRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import com.flarefitness.backend.service.analytics.BehaviorAnalyticsService;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class OrderServiceTest {

    @Mock
    private OrderRepository orderRepository;
    @Mock
    private OrderItemRepository orderItemRepository;
    @Mock
    private CustomerRepository customerRepository;
    @Mock
    private ProductRepository productRepository;
    @Mock
    private ProductVariantRepository productVariantRepository;
    @Mock
    private ProductService productService;
    @Mock
    private VoucherPricingService voucherPricingService;
    @Mock
    private BehaviorAnalyticsService behaviorAnalyticsService;
    @Mock
    private AuditLogService auditLogService;

    private OrderService orderService;
    private Authentication customerAuthentication;
    private Authentication staffAuthentication;
    private Customer customer;

    @BeforeEach
    void setUp() {
        orderService = new OrderService(
                orderRepository,
                orderItemRepository,
                customerRepository,
                productRepository,
                productVariantRepository,
                productService,
                voucherPricingService,
                new ObjectMapper(),
                behaviorAnalyticsService,
                auditLogService
        );

        User user = new User();
        user.setId("user-1");
        user.setUsername("customer");
        user.setPassword("password");
        user.setRole("customer");
        user.setHoTen("Customer");
        user.setStatus("ACTIVE");
        CurrentUserPrincipal principal = new CurrentUserPrincipal(user);
        customerAuthentication = new UsernamePasswordAuthenticationToken(
                principal,
                null,
                principal.getAuthorities()
        );

        User staff = new User();
        staff.setId("staff-1");
        staff.setUsername("staff");
        staff.setPassword("password");
        staff.setRole("staff");
        staff.setHoTen("Staff");
        staff.setStatus("ACTIVE");
        CurrentUserPrincipal staffPrincipal = new CurrentUserPrincipal(staff);
        staffAuthentication = new UsernamePasswordAuthenticationToken(
                staffPrincipal,
                null,
                staffPrincipal.getAuthorities()
        );

        customer = new Customer();
        customer.setId("customer-1");
        customer.setUserId(user.getId());
        customer.setTenKhach("Customer");
        customer.setEmail("customer@example.com");
        customer.setSdt("0900000000");
        customer.setDiaChi("1 Test, Ward, City");
        customer.setDeleted(false);
    }

    @Test
    void createOrderUsesDatabasePriceAndDecrementsLockedStock() {
        Product product = product("product-1", "100.00", 10);
        AtomicReference<List<OrderItem>> savedItems = new AtomicReference<>(List.of());
        mockCustomerLookup();
        when(voucherPricingService.applyVoucher(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> VoucherPricingService.VoucherPricing.none(invocation.getArgument(2)));
        when(productRepository.findAllByIdForUpdate(anyCollection())).thenReturn(List.of(product));
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of(product));
        when(customerRepository.findById(customer.getId())).thenReturn(Optional.of(customer));
        when(orderRepository.saveAndFlush(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(orderRepository.save(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(productRepository.saveAll(anyCollection())).thenAnswer(invocation -> invocation.getArgument(0));
        when(orderItemRepository.saveAll(anyCollection())).thenAnswer(invocation -> {
            savedItems.set(new ArrayList<>(invocation.getArgument(0)));
            return savedItems.get();
        });
        when(orderItemRepository.findByOrderId(any())).thenAnswer(invocation -> savedItems.get());

        OrderRequest request = orderRequest(3, "1.00", "1.00");
        OrderResponse response = orderService.createOrder(customerAuthentication, request);

        assertThat(product.getTonKho()).isEqualTo(7);
        assertThat(response.subtotal()).isEqualByComparingTo("300.00");
        assertThat(response.shipping()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(response.discount()).isEqualByComparingTo(BigDecimal.ZERO);
        assertThat(response.total()).isEqualByComparingTo("300.00");
        assertThat(response.voucherCode()).isBlank();
        assertThat(response.userId()).isEqualTo("user-1");
        assertThat(response.accountKey()).isEqualTo("user-1");
        assertThat(response.accountKeyAliases()).containsExactly("user-1");
        assertThat(response.accountKeyAliases())
                .doesNotContain(customer.getId(), customer.getEmail(), customer.getSdt());
        assertThat(response.items()).singleElement().satisfies(item -> {
            assertThat(item.unitPrice()).isEqualByComparingTo("100.00");
            assertThat(item.subtotal()).isEqualByComparingTo("300.00");
        });
        verify(productRepository).findAllByIdForUpdate(anyCollection());
        verify(orderRepository).saveAndFlush(any(Order.class));
        verify(voucherPricingService).applyVoucher(any(), any(), any(), any(), eq(response.id()));
        verify(productService).evictProductCachesAfterCommit(anyCollection());
        verify(auditLogService).success("ORDER_CREATE", "user-1", "user-1", "ORDER", response.id());
    }

    @Test
    void createOrderRejectsInsufficientStockBeforeSavingOrder() {
        Product product = product("product-1", "100.00", 1);
        mockCustomerLookup();
        when(productRepository.findAllByIdForUpdate(anyCollection())).thenReturn(List.of(product));

        assertThatThrownBy(() -> orderService.createOrder(customerAuthentication, orderRequest(2, "1.00", "1.00")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("khong du ton kho");

        verify(orderRepository, never()).save(any(Order.class));
        verify(orderItemRepository, never()).saveAll(anyCollection());
        verify(productRepository, never()).saveAll(anyCollection());
    }

    @Test
    void legacyOrderListUsesBoundedCursorQuery() {
        ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
        when(orderRepository.findPageBefore(any(), any(), any(Pageable.class))).thenReturn(List.of());

        assertThat(orderService.getAllOrders()).isEmpty();

        verify(orderRepository).findPageBefore(any(), any(), pageable.capture());
        assertThat(pageable.getValue().getPageSize()).isEqualTo(101);
        verify(orderRepository, never()).findAllByOrderByCreatedAtDesc();
    }

    @Test
    void legacyOrderResponseUsesOnlyTheLinkedImmutableUserId() {
        Order legacyOrder = order("order-legacy", "Chờ xác nhận", null);
        legacyOrder.setUserId(null);
        when(orderRepository.findPageBefore(any(), any(), any(Pageable.class))).thenReturn(List.of(legacyOrder));
        when(orderItemRepository.findByOrderIdIn(anyCollection())).thenReturn(List.of());
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of());
        when(customerRepository.findAllById(anyCollection())).thenReturn(List.of(customer));

        OrderResponse response = orderService.getAllOrdersPage(null, null, 20).content().get(0);

        assertThat(response.userId()).isEqualTo("user-1");
        assertThat(response.accountKey()).isEqualTo("user-1");
        assertThat(response.accountKeyAliases()).containsExactly("user-1");
        assertThat(response.accountKeyAliases())
                .doesNotContain(customer.getId(), customer.getEmail(), customer.getSdt());
    }

    @Test
    void createOrderRejectsDuplicateProductVariantLines() {
        mockCustomerLookup();
        OrderItemPayload duplicate = new OrderItemPayload(
                "product-1", null, "SKU-1", "Client product name", "", "M", "Red", 1,
                new BigDecimal("1.00"), new BigDecimal("1.00"));
        OrderRequest request = new OrderRequest(
                null, null, LocalDateTime.now().toString(), BigDecimal.ONE, BigDecimal.ZERO,
                BigDecimal.ZERO, BigDecimal.ONE, "", "", 
                new OrderAddressPayload(null, "Customer", "0900000000", "1 Test", "", "Ward", "", "City", ""),
                List.of(duplicate, duplicate));

        assertThatThrownBy(() -> orderService.createOrder(customerAuthentication, request))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("chi duoc xuat hien mot lan");

        verify(productRepository, never()).findAllByIdForUpdate(anyCollection());
        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void createOrderUsesLockedVariantPriceAndStock() {
        // Variant inventory is authoritative. A stale aggregate on the parent
        // product must not make a sellable variant impossible to purchase.
        Product product = product("product-1", "100.00", 0);
        ProductVariant variant = new ProductVariant();
        variant.setId("variant-1");
        variant.setProductId(product.getId());
        variant.setSku("SKU-1-M-RED");
        variant.setSize("M");
        variant.setMau("Red");
        variant.setGiaBan(new BigDecimal("125.00"));
        variant.setTonKho(5);
        variant.setTrangThai("Dang ban");
        variant.setDeleted(false);
        AtomicReference<List<OrderItem>> savedItems = new AtomicReference<>(List.of());

        mockCustomerLookup();
        when(voucherPricingService.applyVoucher(any(), any(), any(), any(), any()))
                .thenAnswer(invocation -> VoucherPricingService.VoucherPricing.none(invocation.getArgument(2)));
        when(productRepository.findAllByIdForUpdate(anyCollection())).thenReturn(List.of(product));
        when(productVariantRepository.findActiveByProductIdIn(anyCollection())).thenReturn(List.of(variant));
        when(productVariantRepository.findActiveByIdInForUpdate(anyCollection())).thenReturn(List.of(variant));
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of(product));
        when(customerRepository.findById(customer.getId())).thenReturn(Optional.of(customer));
        when(orderRepository.saveAndFlush(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(orderRepository.save(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(productRepository.saveAll(anyCollection())).thenAnswer(invocation -> invocation.getArgument(0));
        when(productVariantRepository.saveAll(anyCollection())).thenAnswer(invocation -> invocation.getArgument(0));
        when(orderItemRepository.saveAll(anyCollection())).thenAnswer(invocation -> {
            savedItems.set(new ArrayList<>(invocation.getArgument(0)));
            return savedItems.get();
        });
        when(orderItemRepository.findByOrderId(any())).thenAnswer(invocation -> savedItems.get());

        OrderRequest request = new OrderRequest(
                null, null, LocalDateTime.now().toString(), BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO,
                null, null,
                new OrderAddressPayload(null, "Customer", "0900000000", "1 Test", "", "Ward", "", "City", ""),
                List.of(new OrderItemPayload(
                        product.getId(), variant.getId(), "untrusted", "untrusted", "untrusted", "untrusted", "untrusted", 2,
                        BigDecimal.ONE, BigDecimal.ONE)));

        OrderResponse response = orderService.createOrder(customerAuthentication, request);

        assertThat(product.getTonKho()).isZero();
        assertThat(variant.getTonKho()).isEqualTo(3);
        assertThat(response.subtotal()).isEqualByComparingTo("250.00");
        assertThat(response.items()).singleElement().satisfies(item -> {
            assertThat(item.variantId()).isEqualTo(variant.getId());
            assertThat(item.sku()).isEqualTo(variant.getSku());
            assertThat(item.unitPrice()).isEqualByComparingTo("125.00");
        });
        verify(productVariantRepository).saveAll(anyCollection());
    }

    @Test
    void createOrderRejectsMoreThanFiftyLinesBeforeLoadingInventory() {
        OrderRequest base = orderRequest(1, "1.00", "1.00");
        List<OrderItemPayload> items = new ArrayList<>();
        for (int index = 0; index < 51; index++) {
            items.add(base.items().get(0));
        }
        OrderRequest oversizedRequest = new OrderRequest(
                base.id(), base.code(), base.createdAt(), base.subtotal(), base.shipping(), base.discount(), base.total(),
                base.voucherCode(), base.voucherLabel(), base.address(), items);

        assertThatThrownBy(() -> orderService.createOrder(customerAuthentication, oversizedRequest))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("toi da 50");

        verify(productRepository, never()).findAllByIdForUpdate(anyCollection());
        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void createOrderRejectsProductThatIsNoLongerSellable() {
        Product product = product("product-1", "100.00", 10);
        product.setTrangThai("Ngung kinh doanh");
        mockCustomerLookup();
        when(productRepository.findAllByIdForUpdate(anyCollection())).thenReturn(List.of(product));
        when(productVariantRepository.findActiveByProductIdIn(anyCollection())).thenReturn(List.of());

        assertThatThrownBy(() -> orderService.createOrder(customerAuthentication, orderRequest(1, "1.00", "1.00")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("dang khong ban");

        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void createOrderDoesNotReturnAnotherUsersIdempotentOrder() {
        Order existing = order("client-order-1", "Chờ xác nhận", null);
        existing.setUserId("user-2");
        when(orderRepository.findById(existing.getId())).thenReturn(Optional.of(existing));
        OrderRequest base = orderRequest(1, "100.00", "100.00");
        OrderRequest request = new OrderRequest(
                existing.getId(),
                base.code(),
                base.createdAt(),
                base.subtotal(),
                base.shipping(),
                base.discount(),
                base.total(),
                base.voucherCode(),
                base.voucherLabel(),
                base.address(),
                base.items());

        assertThatThrownBy(() -> orderService.createOrder(customerAuthentication, request))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("da duoc su dung");

        verify(orderItemRepository, never()).saveAll(anyCollection());
    }

    @Test
    void updateOrderRejectsStatusJump() {
        Order order = order("order-1", "Ch\u1edd x\u00e1c nh\u1eadn", null);
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));

        assertThatThrownBy(() -> orderService.updateOrder(
                order.getId(),
                statusRequest("\u0110\u00e3 giao"),
                staffAuthentication
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Khong the chuyen trang thai");

        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void updateOrderAllowsNextStatusOnly() {
        Order order = order("order-1", "Ch\u1edd x\u00e1c nh\u1eadn", null);
        mockOrderResponse(order);

        OrderResponse response = orderService.updateOrder(
                order.getId(),
                statusRequest("\u0110ang chu\u1ea9n b\u1ecb"),
                staffAuthentication
        );

        assertThat(response.status()).isEqualTo("\u0110ang chu\u1ea9n b\u1ecb");
        verify(orderRepository).save(order);
    }

    @Test
    void paymentConfirmationUsesAuthenticatedStaffAndServerTime() {
        Order order = order("order-1", "\u0110\u00e3 giao", null);
        mockOrderResponse(order);

        OrderResponse response = orderService.updateOrder(
                order.getId(),
                new OrderStatusUpdateRequest(
                        null,
                        "\u0110\u00e3 thu ti\u1ec1n",
                        null,
                        null,
                        null,
                        null,
                        "attacker",
                        "2000-01-01T00:00:00"),
                staffAuthentication);

        assertThat(response.paymentStatus()).contains("th\u00e0nh c\u00f4ng");
        assertThat(response.paymentConfirmedBy()).isEqualTo("staff");
        assertThat(response.paidAt()).isNotBlank().isNotEqualTo("2000-01-01T00:00:00");
        verify(auditLogService).success("ORDER_PAYMENT_CONFIRM", "staff-1", "user-1", "ORDER", order.getId());
    }

    @Test
    void updateOrderRejectsCancellationWithoutApprovedCustomerRequest() {
        Order order = order("order-1", "Ch\u1edd x\u00e1c nh\u1eadn", null);
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));

        assertThatThrownBy(() -> orderService.updateOrder(
                order.getId(),
                statusRequest("\u0110\u00e3 h\u1ee7y"),
                staffAuthentication
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("duyet yeu cau huy");

        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void cancellingReservedOrderRestoresStockOnce() {
        Order order = order(
                "order-1",
                "Ch\u1edd x\u00e1c nh\u1eadn",
                "{\"inventoryReserved\":\"true\",\"supportRequest\":\"Y\u00eau c\u1ea7u h\u1ee7y \u0111\u01a1n\",\"supportStatus\":\"Ch\u1edd duy\u1ec7t\"}"
        );
        Product product = product("product-1", "100.00", 8);
        OrderItem item = new OrderItem();
        item.setProductId(product.getId());
        item.setSoLuong(2);
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));
        when(orderItemRepository.findByOrderId(order.getId())).thenReturn(List.of(item));
        when(productRepository.findAllByIdForUpdate(anyCollection())).thenReturn(List.of(product));
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of(product));
        when(productRepository.saveAll(anyCollection())).thenAnswer(invocation -> invocation.getArgument(0));
        when(orderRepository.save(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(customerRepository.findById(customer.getId())).thenReturn(Optional.of(customer));

        OrderResponse response = orderService.updateOrder(
                order.getId(),
                new OrderStatusUpdateRequest(
                        "\u0110\u00e3 h\u1ee7y",
                        null,
                        null,
                        "\u0110\u00e3 duy\u1ec7t",
                        null,
                        null,
                        null,
                        null
                ),
                staffAuthentication
        );

        assertThat(product.getTonKho()).isEqualTo(10);
        assertThat(response.status()).isEqualTo("\u0110\u00e3 h\u1ee7y");
        assertThat(order.getGhiChu()).contains("\"inventoryRestored\":\"true\"");
        verify(productService).evictProductCachesAfterCommit(anyCollection());
    }

    @Test
    void cancellingNewVariantOrderRestoresOnlyVariantInventory() {
        Order order = order(
                "order-1",
                "Ch\u1edd x\u00e1c nh\u1eadn",
                "{\"inventoryReserved\":\"true\",\"inventoryModel\":\"VARIANT_ONLY_V1\","
                        + "\"supportRequest\":\"Y\u00eau c\u1ea7u h\u1ee7y \u0111\u01a1n\",\"supportStatus\":\"Ch\u1edd duy\u1ec7t\"}"
        );
        Product product = product("product-1", "100.00", 10);
        ProductVariant variant = new ProductVariant();
        variant.setId("variant-1");
        variant.setProductId(product.getId());
        variant.setTonKho(3);
        variant.setDeleted(false);
        OrderItem item = new OrderItem();
        item.setProductId(product.getId());
        item.setVariantId(variant.getId());
        item.setSoLuong(2);
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));
        when(orderItemRepository.findByOrderId(order.getId())).thenReturn(List.of(item));
        when(productVariantRepository.findActiveByIdInForUpdate(anyCollection())).thenReturn(List.of(variant));
        when(productVariantRepository.saveAll(anyCollection())).thenAnswer(invocation -> invocation.getArgument(0));
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of(product));
        when(customerRepository.findById(customer.getId())).thenReturn(Optional.of(customer));
        when(orderRepository.save(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));

        orderService.updateOrder(
                order.getId(),
                new OrderStatusUpdateRequest(
                        "\u0110\u00e3 h\u1ee7y", null, null, "\u0110\u00e3 duy\u1ec7t", null, null, null, null),
                staffAuthentication);

        assertThat(product.getTonKho()).isEqualTo(10);
        assertThat(variant.getTonKho()).isEqualTo(5);
        verify(productRepository, never()).findAllByIdForUpdate(anyCollection());
        verify(productService).evictProductCachesAfterCommit(anyCollection());
    }

    @Test
    void updateOrderRejectsStaffCreatingSupportRequest() {
        Order order = order("order-1", "Ch\u1edd x\u00e1c nh\u1eadn", null);
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));

        assertThatThrownBy(() -> orderService.updateOrder(
                order.getId(),
                new OrderStatusUpdateRequest(
                        null,
                        null,
                        "Y\u00eau c\u1ea7u h\u1ee7y \u0111\u01a1n",
                        "Ch\u1edd duy\u1ec7t",
                        null,
                        null,
                        null,
                        null
                ),
                staffAuthentication
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Chi khach hang moi duoc tao yeu cau");

        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void updateOrderAllowsStaffApprovingExistingReturnRequest() {
        Order order = order(
                "order-1",
                "\u0110\u00e3 giao",
                "{\"supportRequest\":\"Y\u00eau c\u1ea7u \u0111\u1ed5i tr\u1ea3\",\"supportStatus\":\"Ch\u1edd duy\u1ec7t\"}"
        );
        mockOrderResponse(order);

        OrderResponse response = orderService.updateOrder(
                order.getId(),
                new OrderStatusUpdateRequest(
                        null,
                        null,
                        null,
                        "\u0110\u00e3 duy\u1ec7t",
                        null,
                        null,
                        null,
                        null
                ),
                staffAuthentication
        );

        assertThat(response.supportRequest()).isEqualTo("Y\u00eau c\u1ea7u \u0111\u1ed5i tr\u1ea3");
        assertThat(response.supportStatus()).isEqualTo("\u0110\u00e3 duy\u1ec7t");
        verify(orderRepository).save(order);
    }

    @Test
    void updateOrderRejectsStaffDecisionWithoutCustomerRequest() {
        Order order = order("order-1", "\u0110\u00e3 giao", null);
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));

        assertThatThrownBy(() -> orderService.updateOrder(
                order.getId(),
                new OrderStatusUpdateRequest(
                        null,
                        null,
                        null,
                        "\u0110\u00e3 duy\u1ec7t",
                        null,
                        null,
                        null,
                        null
                ),
                staffAuthentication
        ))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("chua co yeu cau");

        verify(orderRepository, never()).save(any(Order.class));
    }

    @Test
    void requestCancellationRejectsStaffCreatingCustomerRequest() {
        assertThatThrownBy(() -> orderService.requestCancellation(
                "order-1",
                statusRequest(null),
                staffAuthentication
        ))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Nhan vien va quan tri vien");

        verify(orderRepository, never()).findByIdForUpdate(any());
    }

    @Test
    void updateOrderRejectsCustomerProcessingOrder() {
        assertThatThrownBy(() -> orderService.updateOrder(
                "order-1",
                statusRequest("\u0110ang chu\u1ea9n b\u1ecb"),
                customerAuthentication
        ))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Chi nhan vien va quan tri vien");

        verify(orderRepository, never()).findByIdForUpdate(any());
    }

    private void mockCustomerLookup() {
        when(customerRepository.findUniqueActiveByUserId("user-1")).thenReturn(Optional.of(customer));
        when(customerRepository.save(any(Customer.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    private void mockOrderResponse(Order order) {
        when(orderRepository.findByIdForUpdate(order.getId())).thenReturn(Optional.of(order));
        when(orderRepository.save(any(Order.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(orderItemRepository.findByOrderId(order.getId())).thenReturn(List.of());
        when(productRepository.findAllById(anyCollection())).thenReturn(List.of());
        when(customerRepository.findById(customer.getId())).thenReturn(Optional.of(customer));
    }

    private OrderRequest orderRequest(int quantity, String clientUnitPrice, String clientTotal) {
        return new OrderRequest(
                null,
                null,
                LocalDateTime.now().toString(),
                new BigDecimal(clientTotal),
                new BigDecimal("999.00"),
                new BigDecimal("999.00"),
                new BigDecimal(clientTotal),
                "UNTRUSTED",
                "Untrusted voucher",
                new OrderAddressPayload(null, "Customer", "0900000000", "1 Test", "", "Ward", "", "City", ""),
                List.of(new OrderItemPayload(
                        "product-1",
                        null,
                        "SKU-1",
                        "Client product name",
                        "",
                        "M",
                        "Red",
                        quantity,
                        new BigDecimal(clientUnitPrice),
                        new BigDecimal(clientTotal)
                ))
        );
    }

    private Product product(String id, String price, int stock) {
        Product product = new Product();
        product.setId(id);
        product.setSku("SKU-1");
        product.setTenSanPham("Database product");
        product.setGiaBan(new BigDecimal(price));
        product.setTonKho(stock);
        return product;
    }

    private Order order(String id, String status, String metadata) {
        Order order = new Order();
        order.setId(id);
        order.setMaDon("DH-1");
        order.setCustomerId(customer.getId());
        order.setUserId("user-1");
        order.setNguoiNhan("Customer");
        order.setSoDienThoaiGiao("0900000000");
        order.setTrangThaiDon(status);
        order.setThanhToan("COD");
        order.setDaThanhToan(false);
        order.setTongTien(new BigDecimal("100.00"));
        order.setPhiShip(BigDecimal.ZERO);
        order.setGiamGia(BigDecimal.ZERO);
        order.setDiaChiGiao("1 Test, Ward, City");
        order.setGhiChu(metadata);
        order.setCreatedAt(LocalDateTime.now());
        order.setUpdatedAt(LocalDateTime.now());
        order.setDeleted(false);
        return order;
    }

    private OrderStatusUpdateRequest statusRequest(String status) {
        return new OrderStatusUpdateRequest(status, null, null, null, null, null, null, null);
    }
}
