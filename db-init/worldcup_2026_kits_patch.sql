USE flare_fitness;

INSERT INTO tbl_san_pham (
    id, ten_san_pham, sku, danh_muc, thuong_hieu, size, mau, gia_nhap, gia_ban,
    ton_kho, trang_thai, link_san_pham, hinh_anh_url, mo_ta_ngan, ghi_chu,
    ngay_tao, ngay_cap_nhat, is_deleted
)
VALUES
    ('product-201', 'Bộ đồ đội tuyển Đức WorldCup 2026', 'WC-001', 'Bóng đá', 'Limited', 'S-XL', 'Đen / Vàng|Đen', 520000, 890000, 28, 'Đang bán', '', './assets/images/products/Bong-Da/WC-001/Black-Gold.png.webp|./assets/images/products/Bong-Da/WC-001/Black.png.webp', 'Bộ áo quần phong cách đội tuyển Đức cho mùa WorldCup 2026, chất vải thể thao thoáng nhẹ, phù hợp mặc cổ vũ và đá bóng phong trào.', 'WorldCup 2026 featured kit.', '2026-05-25 08:00:00', '2026-05-25 08:00:00', 0),
    ('product-202', 'Bộ đồ đội tuyển Pháp WorldCup 2026', 'WC-002', 'Bóng đá', 'Limited', 'S-XL', 'Xanh dương / Trắng|Xanh dương', 540000, 920000, 30, 'Đang bán', '', './assets/images/products/Bong-Da/WC-002/Blue-White.png.webp|./assets/images/products/Bong-Da/WC-002/Blue.png.webp', 'Bộ áo quần phong cách đội tuyển Pháp WorldCup 2026, form thể thao dễ vận động và phối màu xanh navy đặc trưng.', 'WorldCup 2026 featured kit.', '2026-05-25 08:01:00', '2026-05-25 08:01:00', 0),
    ('product-203', 'Bộ đồ đội tuyển Anh WorldCup 2026', 'WC-003', 'Bóng đá', 'Limited', 'S-XL', 'Đỏ|Trắng', 510000, 870000, 24, 'Đang bán', '', './assets/images/products/Bong-Da/WC-003/Red.png.webp|./assets/images/products/Bong-Da/WC-003/White.png.webp', 'Bộ áo quần phong cách đội tuyển Anh cho WorldCup 2026, tông trắng chủ đạo, dễ mặc khi thi đấu hoặc cổ vũ.', 'WorldCup 2026 featured kit.', '2026-05-25 08:02:00', '2026-05-25 08:02:00', 0),
    ('product-204', 'Bộ đồ đội tuyển Brazil WorldCup 2026', 'WC-004', 'Bóng đá', 'Limited', 'S-XL', 'Xanh dương|Vàng', 560000, 950000, 32, 'Đang bán', '', './assets/images/products/Bong-Da/WC-004/Blue.png.webp|./assets/images/products/Bong-Da/WC-004/Yellow.png.webp', 'Bộ áo quần phong cách đội tuyển Brazil WorldCup 2026, phối vàng xanh nổi bật, phù hợp cho fan bóng đá và đội phong trào.', 'WorldCup 2026 featured kit.', '2026-05-25 08:03:00', '2026-05-25 08:03:00', 0),
    ('product-205', 'Bộ đồ đội tuyển Bồ Đào Nha WorldCup 2026', 'WC-005', 'Bóng đá', 'Limited', 'S-XL', 'Đen|Đỏ', 550000, 930000, 29, 'Đang bán', '', './assets/images/products/Bong-Da/WC-005/Black.png.webp|./assets/images/products/Bong-Da/WC-005/Red.png.webp', 'Bộ áo quần phong cách đội tuyển Bồ Đào Nha WorldCup 2026, tông đỏ mạnh mẽ, phù hợp mặc cổ vũ và luyện tập.', 'WorldCup 2026 featured kit.', '2026-05-25 08:04:00', '2026-05-25 08:04:00', 0),
    ('product-206', 'Bộ đồ đội tuyển Tây Ban Nha WorldCup 2026', 'WC-006', 'Bóng đá', 'Limited', 'S-XL', 'Xanh dương|Đỏ', 530000, 900000, 26, 'Đang bán', '', './assets/images/products/Bong-Da/WC-006/Blue.png.webp|./assets/images/products/Bong-Da/WC-006/Red.png.webp', 'Bộ áo quần phong cách đội tuyển Tây Ban Nha WorldCup 2026, phối đỏ vàng nổi bật, chất liệu thể thao nhanh khô.', 'WorldCup 2026 featured kit.', '2026-05-25 08:05:00', '2026-05-25 08:05:00', 0),
    ('product-207', 'Bộ đồ đội tuyển Hàn Quốc WorldCup 2026', 'WC-007', 'Bóng đá', 'Limited', 'S-XL', 'Đen|Tím|Đỏ', 500000, 850000, 23, 'Đang bán', '', './assets/images/products/Bong-Da/WC-007/Black.png.webp|./assets/images/products/Bong-Da/WC-007/Purple.png.webp|./assets/images/products/Bong-Da/WC-007/Red.png.webp', 'Bộ áo quần phong cách đội tuyển Hàn Quốc WorldCup 2026, thiết kế trẻ trung, phù hợp fan châu Á và bóng đá phong trào.', 'WorldCup 2026 featured kit.', '2026-05-25 08:06:00', '2026-05-25 08:06:00', 0),
    ('product-208', 'Bộ đồ đội tuyển Nhật Bản WorldCup 2026', 'WC-008', 'Bóng đá', 'Limited', 'S-XL', 'Tím', 510000, 870000, 25, 'Đang bán', '', './assets/images/products/Bong-Da/WC-008/Purple.png.webp|./assets/images/products/Bong-Da/WC-008/Purple2.png.webp', 'Bộ áo quần phong cách đội tuyển Nhật Bản WorldCup 2026, tông xanh lam đặc trưng, thoáng nhẹ khi vận động.', 'WorldCup 2026 featured kit.', '2026-05-25 08:07:00', '2026-05-25 08:07:00', 0),
    ('product-209', 'Bộ đồ đội tuyển Croatia WorldCup 2026', 'WC-009', 'Bóng đá', 'Limited', 'S-XL', 'Đỏ / Trắng', 520000, 880000, 22, 'Đang bán', '', './assets/images/products/Bong-Da/WC-009/Red-White.png.webp', 'Bộ áo quần phong cách đội tuyển Croatia WorldCup 2026, họa tiết caro đỏ trắng dễ nhận diện, phù hợp cổ vũ và thi đấu.', 'WorldCup 2026 featured kit.', '2026-05-25 08:08:00', '2026-05-25 08:08:00', 0),
    ('product-210', 'Bộ đồ đội tuyển Argentina WorldCup 2026', 'WC-010', 'Bóng đá', 'Limited', 'S-XL', 'Xanh đậm|Trắng / Xanh dương', 520000, 890000, 27, 'Đang bán', '', './assets/images/products/Bong-Da/WC-010/Dark-Blue.png.webp|./assets/images/products/Bong-Da/WC-010/White-Blue.png.webp', 'Bộ áo quần phong cách đội tuyển Argentina WorldCup 2026, thiết kế thể thao thoáng nhẹ, phù hợp mặc cổ vũ và đá bóng phong trào.', 'WorldCup 2026 featured kit.', '2026-05-25 08:09:00', '2026-05-25 08:09:00', 0),
    ('product-211', 'Bộ đồ đội tuyển Uruguay WorldCup 2026', 'WC-011', 'Bóng đá', 'Limited', 'S-XL', 'Xanh dương|Đỏ', 500000, 850000, 21, 'Đang bán', '', './assets/images/products/Bong-Da/WC-011/Blue.png.webp|./assets/images/products/Bong-Da/WC-011/Red.png.webp', 'Bộ áo quần phong cách đội tuyển Uruguay WorldCup 2026, thiết kế thể thao thoáng nhẹ, phù hợp mặc cổ vũ và đá bóng phong trào.', 'WorldCup 2026 featured kit.', '2026-05-25 08:10:00', '2026-05-25 08:10:00', 0),
    ('product-212', 'Bộ đồ đội tuyển Bỉ WorldCup 2026', 'WC-012', 'Bóng đá', 'Limited', 'S-XL', 'Đỏ', 510000, 870000, 24, 'Đang bán', '', './assets/images/products/Bong-Da/WC-012/Red.png.webp', 'Bộ áo quần phong cách đội tuyển Bỉ WorldCup 2026, phối đỏ đen vàng, phù hợp cổ vũ và luyện tập bóng đá.', 'WorldCup 2026 featured kit.', '2026-05-25 08:11:00', '2026-05-25 08:11:00', 0)
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
    hinh_anh_url = VALUES(hinh_anh_url),
    mo_ta_ngan = VALUES(mo_ta_ngan),
    ghi_chu = VALUES(ghi_chu),
    is_deleted = VALUES(is_deleted);

UPDATE tbl_san_pham
SET thuong_hieu = 'Limited'
WHERE sku IN (
    'WC-001', 'WC-002', 'WC-003', 'WC-004', 'WC-005', 'WC-006',
    'WC-007', 'WC-008', 'WC-009', 'WC-010', 'WC-011', 'WC-012',
    'FB-132', 'FB-133', 'FB-134', 'FB-135',
    'BB-126', 'BB-127',
    'VB-129', 'VB-130',
    'TT-130', 'TT-131',
    'BM-128', 'BM-129'
);

