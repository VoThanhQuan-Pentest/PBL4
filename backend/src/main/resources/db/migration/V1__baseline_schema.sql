-- Clean production baseline. Deliberately contains schema only: demo users,
-- customer PII, orders, product samples and test campaigns live in dev/e2e seeds.
CREATE TABLE tbl_nguoi_dung (
    id VARCHAR(64) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    ho_ten VARCHAR(150) NOT NULL,
    email VARCHAR(150) NULL,
    avatar_url VARCHAR(500) NULL,
    trang_thai VARCHAR(30) NOT NULL DEFAULT 'Đang hoạt động',
    lan_dang_nhap_cuoi DATETIME NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_nguoi_dung_username (username),
    KEY idx_tbl_nguoi_dung_email (email),
    KEY idx_tbl_nguoi_dung_role (role),
    KEY idx_tbl_nguoi_dung_trang_thai (trang_thai),
    KEY idx_tbl_nguoi_dung_ngay_tao (ngay_tao)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_khach_hang (
    id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NULL,
    ten_khach VARCHAR(150) NOT NULL,
    sdt VARCHAR(30) NOT NULL,
    email VARCHAR(150) NULL,
    kenh VARCHAR(50) NULL,
    nhan VARCHAR(100) NULL,
    dia_chi VARCHAR(500) NULL,
    ghi_chu VARCHAR(500) NULL,
    tong_chi_tieu DECIMAL(15,2) NOT NULL DEFAULT 0,
    hang_khach_hang VARCHAR(50) NOT NULL DEFAULT 'Thường',
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    sdt_active VARCHAR(30) GENERATED ALWAYS AS (
        CASE WHEN is_deleted = 0 THEN
            CASE WHEN LEFT(sdt, 3) = '+84' THEN CONCAT('0', SUBSTRING(sdt, 4)) ELSE sdt END
        ELSE NULL END
    ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_khach_hang_user_id (user_id),
    UNIQUE KEY uk_tbl_khach_hang_sdt_active (sdt_active),
    KEY idx_tbl_khach_hang_email (email),
    KEY idx_tbl_khach_hang_sdt (sdt),
    KEY idx_tbl_khach_hang_ten_khach (ten_khach),
    KEY idx_tbl_khach_hang_ngay_tao (ngay_tao),
    CONSTRAINT fk_tbl_khach_hang_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_san_pham (
    id VARCHAR(64) NOT NULL,
    ten_san_pham VARCHAR(255) NOT NULL,
    sku VARCHAR(64) NOT NULL,
    danh_muc VARCHAR(100) NOT NULL,
    thuong_hieu VARCHAR(100) NULL,
    size VARCHAR(50) NULL,
    mau VARCHAR(50) NULL,
    gia_nhap DECIMAL(15,2) NOT NULL,
    gia_ban DECIMAL(15,2) NOT NULL,
    ton_kho INT NOT NULL DEFAULT 0,
    trang_thai VARCHAR(50) NOT NULL,
    link_san_pham VARCHAR(500) NULL,
    hinh_anh_url VARCHAR(1500) NULL,
    mo_ta_ngan TEXT NULL,
    ghi_chu VARCHAR(500) NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_san_pham_sku (sku),
    KEY idx_tbl_san_pham_danh_muc (danh_muc),
    KEY idx_tbl_san_pham_trang_thai (trang_thai),
    KEY idx_tbl_san_pham_thuong_hieu (thuong_hieu),
    KEY idx_tbl_san_pham_ngay_tao (ngay_tao),
    KEY idx_tbl_san_pham_filter (danh_muc, thuong_hieu, trang_thai, gia_ban),
    FULLTEXT KEY ftx_tbl_san_pham_search (ten_san_pham, sku, danh_muc, thuong_hieu)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_bien_the_san_pham (
    id VARCHAR(64) NOT NULL,
    product_id VARCHAR(64) NOT NULL,
    sku_bien_the VARCHAR(64) NOT NULL,
    size VARCHAR(50) NOT NULL,
    mau VARCHAR(50) NOT NULL,
    ton_kho_hien_tai INT NOT NULL DEFAULT 0,
    gia_nhap DECIMAL(15,2) NOT NULL,
    gia_ban DECIMAL(15,2) NOT NULL,
    hinh_anh_url VARCHAR(1500) NULL,
    trang_thai VARCHAR(50) NOT NULL DEFAULT 'Đang bán',
    ghi_chu VARCHAR(500) NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_bien_the_san_pham_sku_bien_the (sku_bien_the),
    UNIQUE KEY uk_tbl_bien_the_san_pham_product_size_mau (product_id, size, mau),
    KEY idx_tbl_bien_the_san_pham_product_id (product_id),
    KEY idx_tbl_bien_the_san_pham_trang_thai (trang_thai),
    CONSTRAINT fk_tbl_bien_the_san_pham_product FOREIGN KEY (product_id) REFERENCES tbl_san_pham (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_gio_hang (
    id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NULL,
    customer_id VARCHAR(64) NULL,
    trang_thai VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
    tong_san_pham INT NOT NULL DEFAULT 0,
    tong_tien_tam_tinh DECIMAL(15,2) NOT NULL DEFAULT 0,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_gio_hang_user_id (user_id),
    UNIQUE KEY uk_tbl_gio_hang_customer_id (customer_id),
    KEY idx_tbl_gio_hang_trang_thai (trang_thai),
    CONSTRAINT fk_tbl_gio_hang_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE SET NULL,
    CONSTRAINT fk_tbl_gio_hang_customer FOREIGN KEY (customer_id) REFERENCES tbl_khach_hang (id)
        ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_chi_tiet_gio_hang (
    id VARCHAR(64) NOT NULL,
    cart_id VARCHAR(64) NOT NULL,
    product_id VARCHAR(64) NOT NULL,
    variant_id VARCHAR(64) NOT NULL,
    so_luong INT NOT NULL DEFAULT 1,
    don_gia DECIMAL(15,2) NOT NULL,
    thanh_tien DECIMAL(15,2) NOT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_chi_tiet_gio_hang_cart_variant (cart_id, variant_id),
    KEY idx_tbl_chi_tiet_gio_hang_product_id (product_id),
    CONSTRAINT fk_tbl_chi_tiet_gio_hang_cart FOREIGN KEY (cart_id) REFERENCES tbl_gio_hang (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_tbl_chi_tiet_gio_hang_product FOREIGN KEY (product_id) REFERENCES tbl_san_pham (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_tbl_chi_tiet_gio_hang_variant FOREIGN KEY (variant_id) REFERENCES tbl_bien_the_san_pham (id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_don_hang (
    id VARCHAR(64) NOT NULL,
    ma_don VARCHAR(64) NOT NULL,
    ngay_dat DATE NOT NULL,
    customer_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NULL,
    nguoi_nhan VARCHAR(150) NULL,
    so_dien_thoai_giao VARCHAR(30) NULL,
    trang_thai_don VARCHAR(50) NOT NULL,
    thanh_toan VARCHAR(50) NOT NULL,
    da_thanh_toan TINYINT(1) NOT NULL DEFAULT 0,
    tong_tien DECIMAL(15,2) NOT NULL,
    phi_ship DECIMAL(15,2) NULL DEFAULT 0,
    giam_gia DECIMAL(15,2) NULL DEFAULT 0,
    dia_chi_giao VARCHAR(500) NOT NULL,
    ghi_chu TEXT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_don_hang_ma_don (ma_don),
    KEY idx_tbl_don_hang_customer_id (customer_id),
    KEY idx_tbl_don_hang_user_id (user_id),
    KEY idx_tbl_don_hang_trang_thai_don (trang_thai_don),
    KEY idx_tbl_don_hang_ngay_dat (ngay_dat),
    KEY idx_tbl_don_hang_user_cursor (user_id, ngay_tao, id),
    KEY idx_tbl_don_hang_customer_cursor (customer_id, ngay_tao, id),
    KEY idx_tbl_don_hang_status_cursor (trang_thai_don, ngay_tao, id),
    KEY idx_tbl_don_hang_user_status_cursor (user_id, trang_thai_don, ngay_tao, id),
    KEY idx_tbl_don_hang_paid_date (da_thanh_toan, ngay_dat),
    CONSTRAINT fk_tbl_don_hang_customer FOREIGN KEY (customer_id) REFERENCES tbl_khach_hang (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_tbl_don_hang_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_chi_tiet_don_hang (
    id VARCHAR(64) NOT NULL,
    order_id VARCHAR(64) NOT NULL,
    product_id VARCHAR(64) NOT NULL,
    variant_id VARCHAR(64) NULL,
    ten_san_pham_snapshot VARCHAR(255) NOT NULL,
    sku_snapshot VARCHAR(64) NOT NULL,
    size_snapshot VARCHAR(50) NULL,
    mau_snapshot VARCHAR(50) NULL,
    so_luong INT NOT NULL,
    don_gia DECIMAL(15,2) NOT NULL,
    thanh_tien DECIMAL(15,2) NOT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_chi_tiet_don_hang_order_variant (order_id, sku_snapshot),
    KEY idx_tbl_chi_tiet_don_hang_order_product (order_id, product_id),
    KEY idx_tbl_chi_tiet_don_hang_product_id (product_id),
    KEY idx_tbl_chi_tiet_don_hang_variant_id (variant_id),
    CONSTRAINT fk_tbl_chi_tiet_don_hang_order FOREIGN KEY (order_id) REFERENCES tbl_don_hang (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_tbl_chi_tiet_don_hang_product FOREIGN KEY (product_id) REFERENCES tbl_san_pham (id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_tbl_chi_tiet_don_hang_variant FOREIGN KEY (variant_id) REFERENCES tbl_bien_the_san_pham (id)
        ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_danh_gia_san_pham (
    id VARCHAR(64) NOT NULL,
    product_id VARCHAR(64) NOT NULL,
    order_id VARCHAR(64) NULL,
    user_id VARCHAR(64) NOT NULL,
    reviewer_name VARCHAR(150) NOT NULL,
    rating INT NOT NULL,
    content VARCHAR(1000) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'Hiển thị',
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_danh_gia_order_product_user (order_id, product_id, user_id),
    KEY idx_tbl_danh_gia_product (product_id),
    KEY idx_tbl_danh_gia_order (order_id),
    KEY idx_tbl_danh_gia_user (user_id),
    KEY idx_tbl_danh_gia_status (status),
    KEY idx_tbl_danh_gia_ngay_tao (ngay_tao),
    KEY idx_tbl_danh_gia_product_status_created (product_id, status, ngay_tao),
    KEY idx_tbl_danh_gia_user_product_order (user_id, product_id, order_id),
    CONSTRAINT fk_tbl_danh_gia_order FOREIGN KEY (order_id) REFERENCES tbl_don_hang (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_tbl_danh_gia_product FOREIGN KEY (product_id) REFERENCES tbl_san_pham (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_tbl_danh_gia_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_thanh_toan (
    id VARCHAR(64) NOT NULL,
    order_id VARCHAR(64) NOT NULL,
    ma_giao_dich_truy_xuat VARCHAR(100) NOT NULL,
    phuong_thuc VARCHAR(50) NOT NULL,
    so_tien DECIMAL(15,2) NOT NULL,
    trang_thai VARCHAR(50) NOT NULL,
    nha_cung_cap VARCHAR(100) NULL,
    raw_response_json JSON NULL,
    thanh_toan_luc DATETIME NULL,
    ghi_chu VARCHAR(500) NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_tbl_thanh_toan_ma_giao_dich_truy_xuat (ma_giao_dich_truy_xuat),
    KEY idx_tbl_thanh_toan_order_id (order_id),
    KEY idx_tbl_thanh_toan_trang_thai (trang_thai),
    CONSTRAINT fk_tbl_thanh_toan_order FOREIGN KEY (order_id) REFERENCES tbl_don_hang (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_san_khuyen_mai (
    id VARCHAR(64) NOT NULL,
    voucher_code VARCHAR(64) NOT NULL,
    tong_so_luong INT NOT NULL,
    bat_dau DATETIME NOT NULL,
    ket_thuc DATETIME NOT NULL,
    trang_thai VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_promo_hunt_voucher (voucher_code),
    KEY idx_promo_hunt_time (bat_dau, ket_thuc),
    KEY idx_promo_hunt_status (trang_thai)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_luot_nhan_khuyen_mai (
    id VARCHAR(64) NOT NULL,
    campaign_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    trang_thai VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uk_promo_hunt_claim_user (campaign_id, user_id),
    KEY idx_promo_hunt_claim_campaign (campaign_id),
    KEY idx_promo_hunt_claim_user (user_id),
    KEY idx_promo_hunt_claim_status (trang_thai, is_deleted),
    CONSTRAINT fk_promo_hunt_claim_campaign FOREIGN KEY (campaign_id) REFERENCES tbl_san_khuyen_mai (id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_promo_hunt_claim_user FOREIGN KEY (user_id) REFERENCES tbl_nguoi_dung (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_su_kien_hanh_vi_nguoi_dung (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NULL,
    session_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    page_type VARCHAR(50) NULL,
    page_key VARCHAR(255) NULL,
    product_id VARCHAR(64) NULL,
    order_id VARCHAR(64) NULL,
    category_key VARCHAR(100) NULL,
    brand_key VARCHAR(100) NULL,
    search_keyword VARCHAR(255) NULL,
    price_bucket VARCHAR(50) NULL,
    price_value DECIMAL(15,2) NULL,
    quantity INT NULL,
    duration_seconds INT NULL,
    metadata_json JSON NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_behavior_created_time (ngay_tao),
    INDEX idx_behavior_user_time (user_id, ngay_tao),
    INDEX idx_behavior_session_time (session_id, ngay_tao),
    INDEX idx_behavior_event_time (event_type, ngay_tao),
    INDEX idx_behavior_product_time (product_id, ngay_tao),
    INDEX idx_behavior_category_time (category_key, ngay_tao),
    INDEX idx_behavior_brand_time (brand_key, ngay_tao)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_ho_so_hanh_vi_nguoi_dung (
    user_id VARCHAR(64) PRIMARY KEY,
    favorite_category VARCHAR(100) NULL,
    favorite_brand VARCHAR(100) NULL,
    preferred_price_bucket VARCHAR(50) NULL,
    price_min DECIMAL(15,2) NULL,
    price_max DECIMAL(15,2) NULL,
    top_categories_json JSON NULL,
    top_brands_json JSON NULL,
    top_keywords_json JSON NULL,
    last_viewed_product_id VARCHAR(64) NULL,
    total_interactions INT NOT NULL DEFAULT 0,
    average_stay_seconds INT NOT NULL DEFAULT 0,
    total_purchases INT NOT NULL DEFAULT 0,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_behavior_profile_category (favorite_category),
    INDEX idx_behavior_profile_brand (favorite_brand)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_ho_tro_khach_hang (
    id VARCHAR(64) PRIMARY KEY,
    customer_user_id VARCHAR(64) NOT NULL,
    trang_thai VARCHAR(50) NOT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_support_thread_customer (customer_user_id),
    INDEX idx_support_thread_updated (ngay_cap_nhat)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_tin_nhan_ho_tro (
    id VARCHAR(64) PRIMARY KEY,
    thread_id VARCHAR(64) NOT NULL,
    sender_type VARCHAR(20) NOT NULL,
    sender_user_id VARCHAR(64) NULL,
    noi_dung TEXT NOT NULL,
    ngay_tao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_support_message_thread_created (thread_id, ngay_tao),
    CONSTRAINT fk_support_message_thread FOREIGN KEY (thread_id) REFERENCES tbl_ho_tro_khach_hang (id)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tbl_sync_state (
    id VARCHAR(180) NOT NULL,
    scope VARCHAR(20) NOT NULL,
    owner_id VARCHAR(64) NULL,
    state_key VARCHAR(80) NOT NULL,
    payload LONGTEXT NOT NULL,
    ngay_cap_nhat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_sync_state_scope_owner_key (scope, owner_id, state_key),
    KEY idx_sync_state_scope_key (scope, state_key),
    CONSTRAINT fk_sync_state_user FOREIGN KEY (owner_id) REFERENCES tbl_nguoi_dung(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
