-- Deliberately small, repeatable local-development fixture set.  This file is
-- selected only by the `dev` Spring profile and contains data only (no DDL).
SET NAMES utf8mb4;

INSERT INTO tbl_nguoi_dung (
    id, username, password, role, ho_ten, email, trang_thai, is_deleted
) VALUES
    ('dev-admin-001', 'dev_admin', '$2y$12$2BhAmOdn5bYkhnGSsO/1vukswUVvSpPsgDcRat6pcE2K9MEkQsc/S', 'admin',
        'Development Admin', 'dev.admin@flarefitness.test', 'Đang hoạt động', 0),
    ('dev-customer-001', 'dev_customer', '$2y$12$hKbzHXuwZzUDTh5i1oI8hONp6hZo/3jlUY5WGGSHmXx8p8pdAQA.i', 'customer',
        'Development Customer', 'dev.customer@flarefitness.test', 'Đang hoạt động', 0)
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
    ('dev-customer-profile-001', 'dev-customer-001', 'Development Customer', '0900000001',
        'dev.customer@flarefitness.test', 'Development', 'Demo',
        '123 Demo Street, Ho Chi Minh City', 'Development-only fixture', 0, 'Thường', 0)
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

INSERT INTO tbl_san_pham (
    id, ten_san_pham, sku, danh_muc, thuong_hieu, size, mau, gia_nhap, gia_ban,
    ton_kho, trang_thai, link_san_pham, hinh_anh_url, mo_ta_ngan, ghi_chu, is_deleted
) VALUES
    ('dev-product-001', 'Áo đấu demo WorldCup 2026', 'DEV-WC26-001', 'Bóng đá', 'Flare Demo',
        'M-L', 'Đỏ', 180000, 390000, 12, 'Đang bán', '',
        '/assets/images/catalog/football.svg', 'Sản phẩm dữ liệu mẫu dành riêng cho môi trường phát triển.',
        'Development-only fixture', 0)
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
    ('dev-variant-001', 'dev-product-001', 'DEV-WC26-001-M-DO', 'M', 'Đỏ', 12, 180000, 390000,
        '/assets/images/catalog/football.svg', 'Đang bán', 'Development-only fixture', 0)
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
