-- Disposable browser-test fixtures.  The `e2e` profile is the only profile
-- that discovers this repeatable, data-only Flyway migration.
SET NAMES utf8mb4;

INSERT INTO tbl_nguoi_dung (
    id, username, password, role, ho_ten, email, trang_thai, is_deleted
) VALUES
    ('e2e-admin', 'e2e_admin', '$2y$10$mS3g/3mOmbeQM59Eg05TQ.Zqk57L.6Ssuh2vcBnfvDC1RZ3r5Aq56', 'admin',
        'E2E Admin', 'admin.e2e@flarefitness.test', 'Đang hoạt động', 0),
    ('e2e-staff', 'e2e_staff', '$2y$10$PY7R8xzEFG7Q1ZIjiR2x9u.kVCDFATmREVAyc8IFJDriAr8/tAYsm', 'staff',
        'E2E Staff', 'staff.e2e@flarefitness.test', 'Đang hoạt động', 0),
    ('e2e-customer', 'e2e_customer', '$2y$10$.YoZkjbqz4A7guoe44j0Vu5SRtE8SfJ31//yfin1Zp8Wx.hYbe3yi', 'customer',
        'E2E Customer', 'customer.e2e@flarefitness.test', 'Đang hoạt động', 0)
ON DUPLICATE KEY UPDATE
    password = VALUES(password),
    role = VALUES(role),
    ho_ten = VALUES(ho_ten),
    email = VALUES(email),
    trang_thai = VALUES(trang_thai),
    is_deleted = VALUES(is_deleted);

INSERT INTO tbl_khach_hang (
    id, user_id, ten_khach, sdt, email, kenh, nhan, dia_chi, ghi_chu,
    tong_chi_tieu, hang_khach_hang, is_deleted
) VALUES
    ('e2e-customer-profile', 'e2e-customer', 'E2E Customer', '0900000002',
        'customer.e2e@flarefitness.test', 'E2E', 'Test',
        '1 E2E Test Street, Ho Chi Minh City', 'Disposable E2E fixture', 0, 'Thường', 0)
ON DUPLICATE KEY UPDATE
    user_id = VALUES(user_id),
    ten_khach = VALUES(ten_khach),
    sdt = VALUES(sdt),
    email = VALUES(email),
    kenh = VALUES(kenh),
    nhan = VALUES(nhan),
    dia_chi = VALUES(dia_chi),
    ghi_chu = VALUES(ghi_chu),
    tong_chi_tieu = VALUES(tong_chi_tieu),
    hang_khach_hang = VALUES(hang_khach_hang),
    is_deleted = VALUES(is_deleted);

-- FB-010 belongs to the frontend's "Sản phẩm hot" collection.  The product
-- and its selectable SKU are both stocked so cart/checkout tests exercise the
-- server's variant validation path.
INSERT INTO tbl_san_pham (
    id, ten_san_pham, sku, danh_muc, thuong_hieu, size, mau, gia_nhap, gia_ban,
    ton_kho, trang_thai, link_san_pham, hinh_anh_url, mo_ta_ngan, ghi_chu, is_deleted
) VALUES
    ('e2e-product-fb-010', 'Áo đấu Nike E2E', 'FB-010', 'Bóng đá', 'Nike', 'M', 'Xanh dương',
        250000, 550000, 20, 'Đang bán', '', '/assets/images/catalog/football.svg',
        'Sản phẩm thử nghiệm cho bộ E2E.', 'Disposable E2E fixture', 0)
ON DUPLICATE KEY UPDATE
    ten_san_pham = VALUES(ten_san_pham),
    danh_muc = VALUES(danh_muc),
    thuong_hieu = VALUES(thuong_hieu),
    size = VALUES(size),
    mau = VALUES(mau),
    gia_nhap = VALUES(gia_nhap),
    gia_ban = VALUES(gia_ban),
    ton_kho = VALUES(ton_kho),
    trang_thai = VALUES(trang_thai),
    link_san_pham = VALUES(link_san_pham),
    hinh_anh_url = VALUES(hinh_anh_url),
    mo_ta_ngan = VALUES(mo_ta_ngan),
    ghi_chu = VALUES(ghi_chu),
    is_deleted = VALUES(is_deleted);

INSERT INTO tbl_bien_the_san_pham (
    id, product_id, sku_bien_the, size, mau, ton_kho_hien_tai, gia_nhap, gia_ban,
    hinh_anh_url, trang_thai, ghi_chu, is_deleted
) VALUES
    ('e2e-variant-fb-010-m-blue', 'e2e-product-fb-010', 'FB-010-M-XANH', 'M', 'Xanh dương',
        20, 250000, 550000, '/assets/images/catalog/football.svg', 'Đang bán',
        'Disposable E2E fixture', 0)
ON DUPLICATE KEY UPDATE
    product_id = VALUES(product_id),
    size = VALUES(size),
    mau = VALUES(mau),
    ton_kho_hien_tai = VALUES(ton_kho_hien_tai),
    gia_nhap = VALUES(gia_nhap),
    gia_ban = VALUES(gia_ban),
    hinh_anh_url = VALUES(hinh_anh_url),
    trang_thai = VALUES(trang_thai),
    ghi_chu = VALUES(ghi_chu),
    is_deleted = VALUES(is_deleted);
