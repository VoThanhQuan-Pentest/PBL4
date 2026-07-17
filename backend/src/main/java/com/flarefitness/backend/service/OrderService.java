package com.flarefitness.backend.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.order.OrderAddressPayload;
import com.flarefitness.backend.dto.order.OrderCustomerPayload;
import com.flarefitness.backend.dto.order.OrderItemPayload;
import com.flarefitness.backend.dto.order.OrderRequest;
import com.flarefitness.backend.dto.order.OrderResponse;
import com.flarefitness.backend.dto.order.OrderStatusUpdateRequest;
import com.flarefitness.backend.dto.common.CursorPageResponse;
import com.flarefitness.backend.entity.Customer;
import com.flarefitness.backend.entity.Order;
import com.flarefitness.backend.entity.OrderItem;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.ProductVariant;
import com.flarefitness.backend.entity.User;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.exception.ResourceNotFoundException;
import com.flarefitness.backend.exception.UnauthorizedException;
import com.flarefitness.backend.repository.CustomerRepository;
import com.flarefitness.backend.repository.OrderItemRepository;
import com.flarefitness.backend.repository.OrderRepository;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.ProductVariantRepository;
import com.flarefitness.backend.security.CurrentUserPrincipal;
import java.math.BigDecimal;
import java.text.Normalizer;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OrderService {

    private static final String STATUS_PENDING = "Ch\u1edd x\u00e1c nh\u1eadn";
    private static final String STATUS_PREPARING = "\u0110ang chu\u1ea9n b\u1ecb";
    private static final String STATUS_SHIPPING = "\u0110ang giao";
    private static final String STATUS_DELIVERED = "\u0110\u00e3 giao";
    private static final String STATUS_CANCELLED = "\u0110\u00e3 h\u1ee7y";
    private static final String PAYMENT_PENDING_COD = "Ch\u1edd kh\u00e1ch tr\u1ea3 ti\u1ec1n khi nh\u1eadn h\u00e0ng";
    private static final String PAYMENT_WAITING_CONFIRMATION = "Ch\u1edd nh\u00e2n vi\u00ean x\u00e1c nh\u1eadn thu ti\u1ec1n";
    private static final String PAYMENT_PAID = "Thanh to\u00e1n th\u00e0nh c\u00f4ng";
    private static final String PAYMENT_CANCELLED = "Kh\u00f4ng ghi nh\u1eadn thanh to\u00e1n";
    private static final String REQUEST_CANCEL = "Y\u00eau c\u1ea7u h\u1ee7y \u0111\u01a1n";
    private static final String REQUEST_RETURN = "Y\u00eau c\u1ea7u \u0111\u1ed5i tr\u1ea3";
    private static final String SUPPORT_PENDING = "Ch\u1edd duy\u1ec7t";
    private static final String SUPPORT_APPROVED = "\u0110\u00e3 duy\u1ec7t";
    private static final String SUPPORT_REJECTED = "T\u1eeb ch\u1ed1i";
    private static final int MAX_ORDER_ITEM_LINES = 50;
    private static final int LEGACY_ORDER_LIST_LIMIT = 100;
    // Orders created before variant stock was made authoritative decremented both
    // the parent product and the variant. Keep that behaviour only when restoring
    // those historic orders; all new variant orders use the variant as the source
    // of truth for inventory.
    private static final String INVENTORY_MODEL_VARIANT_ONLY = "VARIANT_ONLY_V1";

    private final OrderRepository orderRepository;
    private final OrderItemRepository orderItemRepository;
    private final CustomerRepository customerRepository;
    private final ProductRepository productRepository;
    private final ProductVariantRepository productVariantRepository;
    private final ProductService productService;
    private final VoucherPricingService voucherPricingService;
    private final ObjectMapper objectMapper;
    private final com.flarefitness.backend.service.analytics.BehaviorAnalyticsService behaviorAnalyticsService;
    private final AuditLogService auditLogService;

    public OrderService(
            OrderRepository orderRepository,
            OrderItemRepository orderItemRepository,
            CustomerRepository customerRepository,
            ProductRepository productRepository,
            ProductVariantRepository productVariantRepository,
            ProductService productService,
            VoucherPricingService voucherPricingService,
            ObjectMapper objectMapper,
            com.flarefitness.backend.service.analytics.BehaviorAnalyticsService behaviorAnalyticsService,
            AuditLogService auditLogService) {
        this.orderRepository = orderRepository;
        this.orderItemRepository = orderItemRepository;
        this.customerRepository = customerRepository;
        this.productRepository = productRepository;
        this.productVariantRepository = productVariantRepository;
        this.productService = productService;
        this.voucherPricingService = voucherPricingService;
        this.objectMapper = objectMapper;
        this.behaviorAnalyticsService = behaviorAnalyticsService;
        this.auditLogService = auditLogService;
    }

    @Transactional(readOnly = true)
    public List<OrderResponse> getAllOrders() {
        return getAllOrdersPage(null, null, LEGACY_ORDER_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public List<OrderResponse> getCurrentCustomerOrders(Authentication authentication) {
        return getCurrentCustomerOrdersPage(authentication, null, null, LEGACY_ORDER_LIST_LIMIT).content();
    }

    @Transactional(readOnly = true)
    public CursorPageResponse<OrderResponse> getAllOrdersPage(String before, String beforeId, Integer limit) {
        int safeLimit = normalizePageLimit(limit);
        LocalDateTime cursorTime = parseCursorDateTime(before);
        String cursorId = cursorTime == null ? null : firstNonBlank(beforeId, "\uffff");
        List<Order> page = orderRepository.findPageBefore(
                cursorTime,
                cursorId,
                PageRequest.of(0, safeLimit + 1));
        return toCursorPage(page, safeLimit);
    }

    @Transactional(readOnly = true)
    public CursorPageResponse<OrderResponse> getCurrentCustomerOrdersPage(
            Authentication authentication,
            String before,
            String beforeId,
            Integer limit) {
        User user = requireUser(authentication);
        String customerId = findCustomerForUser(user).map(Customer::getId).orElse(null);
        int safeLimit = normalizePageLimit(limit);
        LocalDateTime cursorTime = parseCursorDateTime(before);
        String cursorId = cursorTime == null ? null : firstNonBlank(beforeId, "\uffff");
        List<Order> page = orderRepository.findCustomerPageBefore(
                user.getId(),
                customerId,
                cursorTime,
                cursorId,
                PageRequest.of(0, safeLimit + 1));
        return toCursorPage(page, safeLimit);
    }

    @Transactional
    public OrderResponse createOrder(Authentication authentication, OrderRequest request) {
        User user = requireCustomer(authentication);
        if (request == null || request.items() == null || request.items().isEmpty()) {
            throw new BadRequestException("Don hang phai co san pham.");
        }
        if (request.items().size() > MAX_ORDER_ITEM_LINES) {
            throw new BadRequestException("Don hang chi duoc chua toi da 50 dong san pham.");
        }

        String requestedId = trimToNull(request.id());
        if (requestedId != null) {
            var existingOrder = orderRepository.findById(requestedId);
            if (existingOrder.isPresent()) {
                return toResponse(requireOwnedIdempotentOrder(existingOrder.get(), user));
            }
        }
        String requestedCode = trimToNull(request.code());
        if (requestedCode != null) {
            var existingOrder = orderRepository.findByMaDon(requestedCode);
            if (existingOrder.isPresent()) {
                return toResponse(requireOwnedIdempotentOrder(existingOrder.get(), user));
            }
        }

        LocalDateTime createdAt = LocalDateTime.now();
        Customer customer = findOrCreateCustomer(user, request.address());

        Order order = new Order();
        order.setId(requestedId == null ? "order-" + UUID.randomUUID() : requestedId);
        order.setMaDon(requestedCode == null ? buildOrderCode(createdAt) : requestedCode);
        order.setNgayDat(createdAt.toLocalDate());
        order.setCustomerId(customer.getId());
        order.setUserId(user.getId());
        order.setNguoiNhan(firstNonBlank(request.address() == null ? null : request.address().recipient(),
                customer.getTenKhach(), user.getHoTen()));
        order.setSoDienThoaiGiao(
                firstNonBlank(request.address() == null ? null : request.address().phone(), customer.getSdt()));
        order.setTrangThaiDon(STATUS_PENDING);
        order.setThanhToan("COD");
        order.setDaThanhToan(false);
        PreparedOrderItems preparedItems = prepareOrderItems(order, request.items(), createdAt);
        // Persist the parent row before a voucher redemption is written. This
        // makes the redemption's database FK enforceable while the enclosing
        // transaction still rolls back the order and inventory on any failure.
        order.setTongTien(preparedItems.subtotal());
        order.setPhiShip(BigDecimal.ZERO);
        order.setGiamGia(BigDecimal.ZERO);
        order.setDiaChiGiao(buildAddressText(request.address(), customer));
        order.setGhiChu(serializeMetadata(Map.of(
                "inventoryReserved", "true",
                "inventoryModel", INVENTORY_MODEL_VARIANT_ONLY)));
        order.setCreatedAt(createdAt);
        order.setUpdatedAt(createdAt);
        order.setDeleted(false);
        order = orderRepository.saveAndFlush(order);
        VoucherPricingService.VoucherPricing voucherPricing = voucherPricingService.applyVoucher(
                user,
                request.voucherCode(),
                preparedItems.subtotal(),
                preparedItems.products(),
                order.getId());
        order.setTongTien(voucherPricing.total());
        order.setPhiShip(BigDecimal.ZERO);
        order.setGiamGia(voucherPricing.discount());
        order.setGhiChu(serializeMetadata(Map.of(
                "inventoryReserved", "true",
                "inventoryModel", INVENTORY_MODEL_VARIANT_ONLY,
                "voucherCode", voucherPricing.code(),
                "voucherLabel", voucherPricing.label())));
        order.setUpdatedAt(createdAt);
        orderRepository.save(order);
        productRepository.saveAll(preparedItems.products());
        productVariantRepository.saveAll(preparedItems.variants());
        orderItemRepository.saveAll(preparedItems.items());
        behaviorAnalyticsService.recordPurchase(user, order, preparedItems.items());
        productService.evictProductCachesAfterCommit(preparedItems.productIds());
        auditLogService.success("ORDER_CREATE", user.getId(), user.getId(), "ORDER", order.getId());
        return toResponse(order);
    }

    private Order requireOwnedIdempotentOrder(Order order, User user) {
        if (order.getUserId() == null || !order.getUserId().equals(user.getId())) {
            throw new BadRequestException("Ma dinh danh don hang da duoc su dung.");
        }
        return order;
    }

    @Transactional
    public OrderResponse updateOrder(String orderId, OrderStatusUpdateRequest request, Authentication authentication) {
        User user = requireStaffOrAdmin(authentication);
        Order order = orderRepository.findByIdForUpdate(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay don hang."));

        Map<String, String> metadata = parseMetadata(order.getGhiChu());
        validateStaffSupportDecision(metadata, request);
        boolean paymentConfirmationRequested = isPaidRequest(request);
        String nextStatus = trimToNull(request.status());
        if (nextStatus != null) {
            String canonicalNextStatus = requireCanonicalOrderStatus(nextStatus);
            validateStatusTransition(order.getTrangThaiDon(), canonicalNextStatus);
            if (STATUS_CANCELLED.equals(canonicalNextStatus)) {
                validateApprovedCancellation(metadata, request);
                restoreReservedInventory(order, metadata);
                order.setDaThanhToan(false);
                metadata.put("paidAt", "");
                metadata.put("paymentConfirmedBy", "");
            }
            order.setTrangThaiDon(canonicalNextStatus);
        }
        applyStaffSupportDecision(metadata, request);

        if (paymentConfirmationRequested) {
            if (!isDeliveredStatus(order.getTrangThaiDon())) {
                throw new BadRequestException("Chi xac nhan thu tien sau khi don da giao.");
            }
            order.setDaThanhToan(true);
            // Payment audit data must come from the authenticated staff member and the server
            // clock. Client supplied timestamps and staff names are not trustworthy.
            metadata.put("paidAt", LocalDateTime.now().toString());
            metadata.put("paymentConfirmedBy", user.getUsername());
        }

        order.setGhiChu(serializeMetadata(metadata));
        order.setUpdatedAt(LocalDateTime.now());
        orderRepository.save(order);
        if (paymentConfirmationRequested) {
            auditLogService.success("ORDER_PAYMENT_CONFIRM", user.getId(), order.getUserId(), "ORDER", order.getId());
        }
        return toResponse(order);
    }

    @Transactional
    public OrderResponse requestCancellation(String orderId, OrderStatusUpdateRequest request,
            Authentication authentication) {
        User user = requireCustomer(authentication);
        Order order = requireOwnedActiveOrder(orderId, user);
        Map<String, String> metadata = parseMetadata(order.getGhiChu());

        if (!canCustomerRequestCancellation(order.getTrangThaiDon())) {
            throw new BadRequestException("Don hang nay khong con duoc gui yeu cau huy.");
        }
        if (hasSupportRequest(metadata, REQUEST_CANCEL)) {
            throw new BadRequestException("Don hang nay da co yeu cau huy.");
        }

        metadata.put("supportRequest", REQUEST_CANCEL);
        metadata.put("supportStatus", SUPPORT_PENDING);
        putOrRemoveMetadata(metadata, "supportNote", request == null ? "" : request.supportNote());
        order.setGhiChu(serializeMetadata(metadata));
        order.setUpdatedAt(LocalDateTime.now());
        return toResponse(orderRepository.save(order));
    }

    @Transactional
    public OrderResponse requestReturn(String orderId, OrderStatusUpdateRequest request,
            Authentication authentication) {
        User user = requireCustomer(authentication);
        Order order = requireOwnedActiveOrder(orderId, user);
        Map<String, String> metadata = parseMetadata(order.getGhiChu());

        if (!canCustomerRequestReturn(order.getTrangThaiDon())) {
            throw new BadRequestException("Chi co the yeu cau doi tra sau khi don hang da giao hoac hoan thanh.");
        }
        if (hasSupportRequest(metadata, REQUEST_RETURN)) {
            throw new BadRequestException("Don hang nay da co yeu cau doi tra.");
        }

        metadata.put("supportRequest", REQUEST_RETURN);
        metadata.put("supportStatus", SUPPORT_PENDING);
        putOrRemoveMetadata(metadata, "supportNote", request == null ? "" : request.supportNote());
        order.setGhiChu(serializeMetadata(metadata));
        order.setUpdatedAt(LocalDateTime.now());
        return toResponse(orderRepository.save(order));
    }

    // Lock the product and (when present) the canonical product variant. Prices,
    // labels and stock always come from these locked database records.
    private PreparedOrderItems prepareOrderItems(Order order, List<OrderItemPayload> payloads,
            LocalDateTime createdAt) {
        Map<String, Integer> quantitiesByProductId = new LinkedHashMap<>();
        Map<String, Integer> quantitiesByStandaloneProductId = new LinkedHashMap<>();
        Set<String> productVariantLines = new java.util.HashSet<>();
        for (OrderItemPayload payload : payloads) {
            if (payload == null) {
                throw new BadRequestException("San pham trong don hang khong hop le.");
            }
            String productId = trimToNull(payload.productId());
            if (productId == null) {
                throw new BadRequestException("San pham trong don hang khong hop le.");
            }
            String variantId = trimToNull(payload.variantId());
            String productVariantKey = productId + "\u0000" + (variantId == null ? "__product__" : variantId);
            if (!productVariantLines.add(productVariantKey)) {
                throw new BadRequestException("Moi san pham hoac bien the chi duoc xuat hien mot lan trong don hang.");
            }
            int quantity = requirePositiveQuantity(payload.quantity());
            try {
                quantitiesByProductId.merge(productId, quantity, Math::addExact);
                if (variantId == null) {
                    quantitiesByStandaloneProductId.merge(productId, quantity, Math::addExact);
                }
            } catch (ArithmeticException exception) {
                throw new BadRequestException("So luong san pham trong don hang qua lon.");
            }
        }

        List<Product> lockedProducts = productRepository.findAllByIdForUpdate(quantitiesByProductId.keySet());
        Map<String, Product> products = lockedProducts
                .stream()
                .collect(Collectors.toMap(Product::getId, Function.identity()));

        Map<String, List<ProductVariant>> variantsByProductId = productVariantRepository
                .findActiveByProductIdIn(quantitiesByProductId.keySet())
                .stream()
                .collect(Collectors.groupingBy(ProductVariant::getProductId));
        Map<String, Integer> quantitiesByVariantId = new LinkedHashMap<>();

        for (OrderItemPayload payload : payloads) {
            String productId = trimToNull(payload.productId());
            Product product = products.get(productId);
            if (product == null) {
                throw new BadRequestException("San pham trong don hang khong ton tai: " + payload.productId());
            }
            if (!isSellableProduct(product)) {
                throw new BadRequestException("San pham dang khong ban: " + product.getTenSanPham());
            }
            String variantId = trimToNull(payload.variantId());
            boolean hasVariants = !variantsByProductId.getOrDefault(productId, List.of()).isEmpty();
            if (hasVariants && variantId == null) {
                throw new BadRequestException("San pham nay yeu cau chon bien the hop le.");
            }
            if (!hasVariants && variantId != null) {
                throw new BadRequestException("Bien the san pham khong hop le.");
            }
            if (variantId != null) {
                try {
                    quantitiesByVariantId.merge(variantId, requirePositiveQuantity(payload.quantity()), Math::addExact);
                } catch (ArithmeticException exception) {
                    throw new BadRequestException("So luong bien the trong don hang qua lon.");
                }
            }
        }

        List<ProductVariant> lockedVariants = quantitiesByVariantId.isEmpty()
                ? List.of()
                : productVariantRepository.findActiveByIdInForUpdate(quantitiesByVariantId.keySet());
        Map<String, ProductVariant> variants = lockedVariants.stream()
                .collect(Collectors.toMap(ProductVariant::getId, Function.identity()));
        for (OrderItemPayload payload : payloads) {
            String variantId = trimToNull(payload.variantId());
            if (variantId == null) {
                continue;
            }
            ProductVariant variant = variants.get(variantId);
            if (variant == null || !variant.getProductId().equals(trimToNull(payload.productId())) || !isSellableVariant(variant)) {
                throw new BadRequestException("Bien the san pham khong hop le.");
            }
        }

        // A product without variants owns its stock. For products with variants,
        // the variant is the authoritative inventory record, so do not also
        // decrement the parent aggregate.
        for (Map.Entry<String, Integer> entry : quantitiesByStandaloneProductId.entrySet()) {
            Product product = products.get(entry.getKey());
            if (product == null) {
                throw new BadRequestException("San pham trong don hang khong ton tai: " + entry.getKey());
            }
            int stock = product.getTonKho() == null ? 0 : product.getTonKho();
            if (stock < entry.getValue()) {
                throw new BadRequestException("San pham khong du ton kho: " + product.getTenSanPham());
            }
            product.setTonKho(stock - entry.getValue());
        }
        for (Map.Entry<String, Integer> entry : quantitiesByVariantId.entrySet()) {
            ProductVariant variant = variants.get(entry.getKey());
            int stock = variant == null || variant.getTonKho() == null ? 0 : variant.getTonKho();
            if (stock < entry.getValue()) {
                throw new BadRequestException("Bien the san pham khong du ton kho.");
            }
            variant.setTonKho(stock - entry.getValue());
        }

        List<OrderItem> items = new ArrayList<>();
        BigDecimal subtotal = BigDecimal.ZERO;
        for (OrderItemPayload payload : payloads) {
            Product product = products.get(trimToNull(payload.productId()));
            if (product == null) {
                throw new BadRequestException("San pham trong don hang khong ton tai: " + payload.productId());
            }

            int quantity = requirePositiveQuantity(payload.quantity());
            ProductVariant variant = trimToNull(payload.variantId()) == null
                    ? null
                    : variants.get(trimToNull(payload.variantId()));
            BigDecimal unitPrice = variant == null ? requireProductPrice(product) : requireVariantPrice(variant);
            BigDecimal lineTotal = unitPrice.multiply(BigDecimal.valueOf(quantity));

            OrderItem item = new OrderItem();
            item.setId("order-item-" + UUID.randomUUID());
            item.setOrderId(order.getId());
            item.setProductId(product.getId());
            item.setVariantId(variant == null ? null : variant.getId());
            item.setTenSanPhamSnapshot(product.getTenSanPham());
            item.setSkuSnapshot(variant == null ? product.getSku() : variant.getSku());
            item.setSizeSnapshot(variant == null
                    ? firstNonBlank(product.getSize(), "Tieu chuan")
                    : variant.getSize());
            item.setMauSnapshot(variant == null ? product.getMau() : variant.getMau());
            item.setSoLuong(quantity);
            item.setDonGia(unitPrice);
            item.setThanhTien(lineTotal);
            item.setCreatedAt(createdAt);
            items.add(item);
            subtotal = subtotal.add(lineTotal);
        }

        return new PreparedOrderItems(
                items,
                lockedProducts,
                lockedVariants,
                subtotal,
                Set.copyOf(quantitiesByProductId.keySet()));
    }

    private int requirePositiveQuantity(Integer quantity) {
        if (quantity == null || quantity < 1 || quantity > 10) {
            throw new BadRequestException("So luong moi san pham phai tu 1 den 10.");
        }
        return quantity;
    }

    private BigDecimal requireProductPrice(Product product) {
        BigDecimal price = product.getGiaBan();
        if (price == null || price.signum() < 0) {
            throw new BadRequestException("Gia ban san pham khong hop le: " + product.getTenSanPham());
        }
        return price;
    }

    private BigDecimal requireVariantPrice(ProductVariant variant) {
        BigDecimal price = variant.getGiaBan();
        if (price == null || price.signum() < 0) {
            throw new BadRequestException("Gia ban bien the san pham khong hop le: " + variant.getSku());
        }
        return price;
    }

    private boolean isSellableProduct(Product product) {
        String status = normalize(product.getTrangThai());
        return !status.contains("ngung")
                && !status.contains("tam khoa")
                && !status.contains("deleted")
                && !status.contains("inactive")
                && !status.contains("khong ban");
    }

    private boolean isSellableVariant(ProductVariant variant) {
        String status = normalize(variant.getTrangThai());
        return !status.contains("ngung")
                && !status.contains("tam khoa")
                && !status.contains("deleted")
                && !status.contains("inactive")
                && !status.contains("khong ban");
    }

    private void restoreReservedInventory(Order order, Map<String, String> metadata) {
        if (!"true".equalsIgnoreCase(metadata.get("inventoryReserved"))
                || "true".equalsIgnoreCase(metadata.get("inventoryRestored"))) {
            return;
        }

        Map<String, Integer> quantitiesByProductId = new LinkedHashMap<>();
        Map<String, Integer> quantitiesByVariantId = new LinkedHashMap<>();
        Set<String> affectedProductIds = new java.util.LinkedHashSet<>();
        boolean restoreParentProductForVariant = !INVENTORY_MODEL_VARIANT_ONLY.equals(metadata.get("inventoryModel"));
        for (OrderItem item : orderItemRepository.findByOrderId(order.getId())) {
            String productId = trimToNull(item.getProductId());
            String variantId = trimToNull(item.getVariantId());
            Integer quantity = item.getSoLuong();
            if (productId == null || quantity == null || quantity < 1) {
                throw new BadRequestException("Don hang co chi tiet ton kho khong hop le.");
            }
            affectedProductIds.add(productId);
            try {
                if (variantId == null || restoreParentProductForVariant) {
                    quantitiesByProductId.merge(productId, quantity, Math::addExact);
                }
            } catch (ArithmeticException exception) {
                throw new BadRequestException("Khong the hoan ton kho cho don hang nay.");
            }
            if (variantId != null) {
                try {
                    quantitiesByVariantId.merge(variantId, quantity, Math::addExact);
                } catch (ArithmeticException exception) {
                    throw new BadRequestException("Khong the hoan ton kho bien the cho don hang nay.");
                }
            }
        }
        if (quantitiesByProductId.isEmpty() && quantitiesByVariantId.isEmpty()) {
            throw new BadRequestException("Don hang khong co chi tiet de hoan ton kho.");
        }

        List<Product> products = quantitiesByProductId.isEmpty()
                ? List.of()
                : productRepository.findAllByIdForUpdate(quantitiesByProductId.keySet());
        Map<String, Product> productsById = products.stream()
                .collect(Collectors.toMap(Product::getId, Function.identity()));
        for (Map.Entry<String, Integer> entry : quantitiesByProductId.entrySet()) {
            Product product = productsById.get(entry.getKey());
            if (product == null) {
                throw new BadRequestException("Khong the hoan ton kho vi san pham khong con ton tai.");
            }
            try {
                product.setTonKho(Math.addExact(
                        product.getTonKho() == null ? 0 : product.getTonKho(),
                        entry.getValue()));
            } catch (ArithmeticException exception) {
                throw new BadRequestException("Khong the hoan ton kho cho don hang nay.");
            }
        }

        List<ProductVariant> variants = quantitiesByVariantId.isEmpty()
                ? List.of()
                : productVariantRepository.findActiveByIdInForUpdate(quantitiesByVariantId.keySet());
        Map<String, ProductVariant> variantsById = variants.stream()
                .collect(Collectors.toMap(ProductVariant::getId, Function.identity()));
        for (Map.Entry<String, Integer> entry : quantitiesByVariantId.entrySet()) {
            ProductVariant variant = variantsById.get(entry.getKey());
            if (variant == null) {
                throw new BadRequestException("Khong the hoan ton kho vi bien the khong con ton tai.");
            }
            try {
                variant.setTonKho(Math.addExact(variant.getTonKho() == null ? 0 : variant.getTonKho(), entry.getValue()));
            } catch (ArithmeticException exception) {
                throw new BadRequestException("Khong the hoan ton kho bien the cho don hang nay.");
            }
        }

        productRepository.saveAll(products);
        productVariantRepository.saveAll(variants);
        productService.evictProductCachesAfterCommit(affectedProductIds);
        metadata.put("inventoryRestored", "true");
    }

    private String requireCanonicalOrderStatus(String status) {
        String canonical = canonicalOrderStatus(status);
        if (canonical == null) {
            throw new BadRequestException("Trang thai don hang khong hop le.");
        }
        return canonical;
    }

    private String canonicalOrderStatus(String status) {
        return switch (normalize(status)) {
            case "cho xac nhan" -> STATUS_PENDING;
            case "dang chuan bi" -> STATUS_PREPARING;
            case "dang giao" -> STATUS_SHIPPING;
            case "da giao", "hoan tat", "hoan thanh" -> STATUS_DELIVERED;
            case "da huy", "huy don", "cancelled", "canceled" -> STATUS_CANCELLED;
            default -> null;
        };
    }

    private void validateStatusTransition(String currentStatus, String nextStatus) {
        String current = canonicalOrderStatus(currentStatus);
        if (current == null) {
            throw new BadRequestException("Trang thai hien tai cua don hang khong hop le.");
        }
        if (current.equals(nextStatus)) {
            return;
        }

        boolean allowed = (STATUS_PENDING.equals(current)
                && (STATUS_PREPARING.equals(nextStatus) || STATUS_CANCELLED.equals(nextStatus)))
                || (STATUS_PREPARING.equals(current)
                        && (STATUS_SHIPPING.equals(nextStatus) || STATUS_CANCELLED.equals(nextStatus)))
                || (STATUS_SHIPPING.equals(current) && STATUS_DELIVERED.equals(nextStatus));
        if (!allowed) {
            throw new BadRequestException("Khong the chuyen trang thai don hang tu '"
                    + current + "' sang '" + nextStatus + "'.");
        }
    }

    private void validateApprovedCancellation(Map<String, String> metadata, OrderStatusUpdateRequest request) {
        String supportStatus = firstNonBlank(request.supportStatus(), metadata.get("supportStatus"));
        if (!hasSupportRequest(metadata, REQUEST_CANCEL) || !"da duyet".equals(normalize(supportStatus))) {
            throw new BadRequestException("Chi co the huy don sau khi duyet yeu cau huy cua khach hang.");
        }
    }

    private void validateStaffSupportDecision(Map<String, String> metadata, OrderStatusUpdateRequest request) {
        if (request.supportRequest() != null) {
            throw new BadRequestException("Chi khach hang moi duoc tao yeu cau huy don hoac doi tra.");
        }

        boolean hasSupportStatus = request.supportStatus() != null;
        boolean hasSupportNote = request.supportNote() != null;
        if (!hasSupportStatus && !hasSupportNote) {
            return;
        }
        if (!hasSupportStatus) {
            throw new BadRequestException("Nhan vien chi duoc cap nhat ghi chu khi duyet hoac tu choi yeu cau.");
        }
        if (trimToNull(metadata.get("supportRequest")) == null) {
            throw new BadRequestException("Don hang chua co yeu cau huy don hoac doi tra tu khach hang.");
        }
        if (!"cho duyet".equals(normalize(metadata.get("supportStatus")))) {
            throw new BadRequestException("Yeu cau nay da duoc xu ly.");
        }

        String decision = normalize(request.supportStatus());
        if (!"da duyet".equals(decision) && !"tu choi".equals(decision)) {
            throw new BadRequestException("Nhan vien chi duoc duyet hoac tu choi yeu cau.");
        }
        if ("da duyet".equals(decision)
                && hasSupportRequest(metadata, REQUEST_CANCEL)
                && !STATUS_CANCELLED.equals(canonicalOrderStatus(request.status()))) {
            throw new BadRequestException("Duyet yeu cau huy phai chuyen don hang sang trang thai Da huy.");
        }
    }

    private void applyStaffSupportDecision(Map<String, String> metadata, OrderStatusUpdateRequest request) {
        if (request.supportStatus() == null) {
            return;
        }
        String decision = normalize(request.supportStatus());
        metadata.put("supportStatus", "da duyet".equals(decision) ? SUPPORT_APPROVED : SUPPORT_REJECTED);
        putOrRemoveMetadata(metadata, "supportNote", request.supportNote());
    }

    // Hàm ghép Id đơn hàng với danh sách chi tiết
    private List<OrderResponse> toResponses(List<Order> orders) {
        if (orders.isEmpty()) {
            return List.of();
        }
        List<String> orderIds = orders.stream().map(Order::getId).toList();
        Map<String, List<OrderItem>> itemsByOrderId = orderItemRepository.findByOrderIdIn(orderIds)
                .stream()
                .collect(Collectors.groupingBy(OrderItem::getOrderId));
        List<String> productIds = itemsByOrderId.values()
                .stream()
                .flatMap(List::stream)
                .map(OrderItem::getProductId)
                .distinct()
                .toList();
        Map<String, Product> products = productRepository.findAllById(productIds)
                .stream()
                .collect(Collectors.toMap(Product::getId, Function.identity()));
        Map<String, Customer> customers = customerRepository
                .findAllById(orders.stream().map(Order::getCustomerId).distinct().toList())
                .stream()
                .collect(Collectors.toMap(Customer::getId, Function.identity()));

        return orders.stream()
                .map(order -> toResponse(order, itemsByOrderId.getOrDefault(order.getId(), List.of()), products,
                        customers.get(order.getCustomerId())))
                .toList();
    }

    private CursorPageResponse<OrderResponse> toCursorPage(List<Order> orders, int limit) {
        boolean hasMore = orders.size() > limit;
        List<Order> pageOrders = hasMore ? orders.subList(0, limit) : orders;
        List<OrderResponse> content = toResponses(pageOrders);
        Order lastOrder = pageOrders.isEmpty() ? null : pageOrders.get(pageOrders.size() - 1);
        return new CursorPageResponse<>(
                content,
                lastOrder == null || lastOrder.getCreatedAt() == null ? null : lastOrder.getCreatedAt().toString(),
                lastOrder == null ? null : lastOrder.getId(),
                hasMore);
    }

    private OrderResponse toResponse(Order order) {
        List<OrderItem> items = orderItemRepository.findByOrderId(order.getId());
        Map<String, Product> products = productRepository
                .findAllById(items.stream().map(OrderItem::getProductId).distinct().toList())
                .stream()
                .collect(Collectors.toMap(Product::getId, Function.identity()));
        Customer customer = customerRepository.findById(order.getCustomerId()).orElse(null);
        return toResponse(order, items, products, customer);
    }

    private OrderResponse toResponse(Order order, List<OrderItem> items, Map<String, Product> products,
            Customer customer) {
        Map<String, String> metadata = parseMetadata(order.getGhiChu());
        List<OrderItemPayload> itemResponses = items.stream()
                .map(item -> {
                    Product product = products.get(item.getProductId());
            return new OrderItemPayload(
                    item.getProductId(),
                    item.getVariantId(),
                    item.getSkuSnapshot(),
                            item.getTenSanPhamSnapshot(),
                            product == null ? "" : product.getHinhAnhUrl(),
                            item.getSizeSnapshot(),
                            item.getMauSnapshot(),
                            item.getSoLuong(),
                            item.getDonGia(),
                            item.getThanhTien());
                })
                .toList();

        int totalItems = itemResponses.stream().mapToInt(item -> item.quantity() == null ? 0 : item.quantity()).sum();
        String paymentStatus = resolvePaymentStatus(order);
        // user_id is the only identity that may be used to associate an order with
        // an account. Legacy orders can safely inherit it from their already-linked
        // customer record, but never from a name, email, phone number or address.
        String resolvedUserId = firstNonBlank(order.getUserId(), customer == null ? null : customer.getUserId());
        OrderCustomerPayload customerPayload = new OrderCustomerPayload(
                firstNonBlank(resolvedUserId, order.getCustomerId()),
                firstNonBlank(customer == null ? null : customer.getTenKhach(), order.getNguoiNhan()),
                "",
                customer == null ? "" : customer.getEmail(),
                firstNonBlank(order.getSoDienThoaiGiao(), customer == null ? null : customer.getSdt()));

        return new OrderResponse(
                order.getId(),
                order.getMaDon(),
                order.getCreatedAt(),
                order.getTrangThaiDon(),
                paymentStatus,
                metadata.getOrDefault("paidAt", ""),
                metadata.getOrDefault("paymentConfirmedBy", ""),
                metadata.getOrDefault("supportRequest", ""),
                metadata.getOrDefault("supportStatus", ""),
                metadata.getOrDefault("supportNote", ""),
                totalItems,
                order.getTongTien().add(nonNegative(order.getGiamGia())).subtract(nonNegative(order.getPhiShip()))
                        .max(BigDecimal.ZERO),
                nonNegative(order.getPhiShip()),
                nonNegative(order.getGiamGia()),
                order.getTongTien(),
                metadata.getOrDefault("voucherCode", ""),
                metadata.getOrDefault("voucherLabel", ""),
                new OrderAddressPayload("", order.getNguoiNhan(), order.getSoDienThoaiGiao(), order.getDiaChiGiao(), "",
                        "", "", "", order.getDiaChiGiao()),
                customerPayload,
                resolvedUserId,
                resolvedUserId,
                resolvedUserId == null ? List.of() : List.of(resolvedUserId),
                itemResponses);
    }

    private Customer findOrCreateCustomer(User user, OrderAddressPayload address) {
        Customer customer = findCustomerForUser(user).orElseGet(Customer::new);
        if (customer.getId() == null || customer.getId().isBlank()) {
            customer.setId("customer-" + UUID.randomUUID());
            customer.setCreatedAt(LocalDateTime.now());
        }
        customer.setUserId(user.getId());
        customer.setTenKhach(
                firstNonBlank(address == null ? null : address.recipient(), user.getHoTen(), user.getUsername()));
        customer.setEmail(user.getEmail());
        customer.setSdt(firstNonBlank(address == null ? null : address.phone(), customer.getSdt(), "0000000000"));
        customer.setKenh(firstNonBlank(customer.getKenh(), "Website"));
        customer.setNhan(firstNonBlank(customer.getNhan(), "Moi"));
        customer.setDiaChi(buildAddressText(address, customer));
        if (customer.getCreatedAt() == null) {
            customer.setCreatedAt(LocalDateTime.now());
        }
        customer.setUpdatedAt(LocalDateTime.now());
        customer.setDeleted(false);
        return customerRepository.save(customer);
    }

    private java.util.Optional<Customer> findCustomerForUser(User user) {
        return customerRepository.findUniqueActiveByUserId(user.getId());
    }

    private Order requireOwnedActiveOrder(String orderId, User user) {
        Order order = orderRepository.findByIdForUpdate(orderId)
                .orElseThrow(() -> new ResourceNotFoundException("Khong tim thay don hang."));
        if (Boolean.TRUE.equals(order.getDeleted())) {
            throw new ResourceNotFoundException("Khong tim thay don hang.");
        }

        boolean belongsToUser = String.valueOf(order.getUserId()).equals(String.valueOf(user.getId()));
        boolean belongsToCustomer = findCustomerForUser(user)
                .map(customer -> String.valueOf(customer.getId()).equals(String.valueOf(order.getCustomerId())))
                .orElse(false);
        if (!belongsToUser && !belongsToCustomer) {
            throw new UnauthorizedException("Ban khong co quyen thao tac voi don hang nay.");
        }
        return order;
    }

    private User requireUser(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CurrentUserPrincipal principal)) {
            throw new UnauthorizedException("Phien dang nhap khong hop le.");
        }
        return principal.getUser();
    }

    private User requireCustomer(Authentication authentication) {
        User user = requireUser(authentication);
        String authority = CurrentUserPrincipal.toAuthority(user.getRole());
        if ("ROLE_ADMIN".equals(authority) || "ROLE_STAFF".equals(authority)) {
            throw new UnauthorizedException("Nhan vien va quan tri vien khong duoc dat hang.");
        }
        return user;
    }

    private User requireStaffOrAdmin(Authentication authentication) {
        User user = requireUser(authentication);
        String authority = CurrentUserPrincipal.toAuthority(user.getRole());
        if (!"ROLE_ADMIN".equals(authority) && !"ROLE_STAFF".equals(authority)) {
            throw new UnauthorizedException("Chi nhan vien va quan tri vien duoc xu ly don hang.");
        }
        return user;
    }

    private String resolvePaymentStatus(Order order) {
        if (Boolean.TRUE.equals(order.getDaThanhToan())) {
            return PAYMENT_PAID;
        }
        if (isCancelledStatus(order.getTrangThaiDon())) {
            return PAYMENT_CANCELLED;
        }
        if (isDeliveredStatus(order.getTrangThaiDon())) {
            return PAYMENT_WAITING_CONFIRMATION;
        }
        return PAYMENT_PENDING_COD;
    }

    private boolean isPaidRequest(OrderStatusUpdateRequest request) {
        String paymentStatus = normalize(request.paymentStatus());
        return paymentStatus.contains("thanh toan thanh cong")
                || paymentStatus.contains("da thu tien")
                || paymentStatus.contains("da ghi nhan thanh toan");
    }

    private boolean isDeliveredStatus(String status) {
        String normalized = normalize(status);
        String raw = String.valueOf(status == null ? "" : status).toLowerCase(Locale.ROOT);
        return normalized.contains("da giao")
                || normalized.contains("hoan tat")
                || normalized.contains("hoan thanh")
                || (raw.contains("giao") && !raw.contains("ang giao"));
    }

    private boolean isCancelledStatus(String status) {
        String normalized = normalize(status);
        String raw = String.valueOf(status == null ? "" : status).toLowerCase(Locale.ROOT);
        return normalized.contains("da huy") || normalized.contains("huy don")
                || (raw.contains("h") && raw.contains("y") && !raw.contains("thay"));
    }

    private boolean canCustomerRequestCancellation(String status) {
        String normalized = normalize(status);
        return !normalized.contains("dang giao")
                && !normalized.contains("da giao")
                && !normalized.contains("hoan tat")
                && !normalized.contains("hoan thanh")
                && !isCancelledStatus(status);
    }

    private boolean canCustomerRequestReturn(String status) {
        return isDeliveredStatus(status) && !isCancelledStatus(status);
    }

    private boolean hasSupportRequest(Map<String, String> metadata, String requestType) {
        String currentRequest = normalize(metadata.get("supportRequest"));
        return !currentRequest.isBlank() && currentRequest.contains(normalize(requestType));
    }

    private Map<String, String> parseMetadata(String note) {
        if (note == null || note.isBlank() || !note.trim().startsWith("{")) {
            return new HashMap<>();
        }
        try {
            return new HashMap<>(objectMapper.readValue(note, new TypeReference<Map<String, String>>() {
            }));
        } catch (JsonProcessingException ignored) {
            return new HashMap<>();
        }
    }

    private String serializeMetadata(Map<String, String> metadata) {
        Map<String, String> clean = new LinkedHashMap<>();
        metadata.forEach((key, value) -> {
            if (value != null && !value.isBlank()) {
                clean.put(key, value);
            }
        });
        if (clean.isEmpty()) {
            return null;
        }
        try {
            String json = objectMapper.writeValueAsString(clean);
            return json;
        } catch (JsonProcessingException exception) {
            return null;
        }
    }

    private String buildAddressText(OrderAddressPayload address, Customer customer) {
        if (address == null) {
            return firstNonBlank(customer.getDiaChi(), "Chua cap nhat dia chi");
        }
        String composedAddress = java.util.stream.Stream
                .of(address.detail(), address.street(), address.ward(), address.district(), address.province())
                .map(this::trimToNull)
                .filter(value -> value != null && !value.isBlank())
                .distinct()
                .collect(Collectors.joining(", "));
        return firstNonBlank(composedAddress, address.text(), customer.getDiaChi(), "Chua cap nhat dia chi");
    }

    private String buildOrderCode(LocalDateTime createdAt) {
        return "DH-" + createdAt.toLocalDate().toString().replace("-", "") + "-"
                + UUID.randomUUID().toString().substring(0, 4).toUpperCase(Locale.ROOT);
    }

    private LocalDateTime parseDateTime(String value) {
        String normalized = trimToNull(value);
        if (normalized == null) {
            return LocalDateTime.now();
        }
        try {
            return Instant.parse(normalized).atZone(ZoneId.systemDefault()).toLocalDateTime();
        } catch (RuntimeException ignored) {
            try {
                return LocalDateTime.parse(normalized);
            } catch (RuntimeException ignoredAgain) {
                return LocalDate.now().atStartOfDay();
            }
        }
    }

    private LocalDateTime parseCursorDateTime(String value) {
        String normalized = trimToNull(value);
        if (normalized == null) {
            return null;
        }
        try {
            return LocalDateTime.parse(normalized);
        } catch (RuntimeException exception) {
            throw new BadRequestException("Con tro phan trang don hang khong hop le.");
        }
    }

    private int normalizePageLimit(Integer limit) {
        return Math.min(Math.max(limit == null ? 25 : limit, 1), 100);
    }

    private BigDecimal nonNegative(BigDecimal value) {
        if (value == null || value.signum() < 0) {
            return BigDecimal.ZERO;
        }
        return value;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            String trimmed = trimToNull(value);
            if (trimmed != null) {
                return trimmed;
            }
        }
        return "";
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private void putOrRemoveMetadata(Map<String, String> metadata, String key, String value) {
        if (value == null) {
            return;
        }
        String trimmed = value.trim();
        if (trimmed.isBlank()) {
            metadata.remove(key);
            return;
        }
        metadata.put(key, trimmed);
    }

    private String normalize(String value) {
        return Normalizer.normalize(String.valueOf(value == null ? "" : value), Normalizer.Form.NFD)
                .toLowerCase(Locale.ROOT)
                .replace('\u0111', 'd')
                .replace('\u0110', 'd')
                .replaceAll("\\p{M}+", "")
                .replaceAll("[^a-z0-9]+", " ")
                .replaceAll("\\s+", " ")
                .trim();
    }

    private record PreparedOrderItems(
            List<OrderItem> items,
            List<Product> products,
            List<ProductVariant> variants,
            BigDecimal subtotal,
            Set<String> productIds) {
    }
}
