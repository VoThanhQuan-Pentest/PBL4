UPDATE tbl_san_pham
SET ten_san_pham = CASE sku
    WHEN 'WC-001' THEN 'Bộ đồ đội tuyển Đức WorldCup 2026'
    WHEN 'WC-002' THEN 'Bộ đồ đội tuyển Pháp WorldCup 2026'
    WHEN 'WC-003' THEN 'Bộ đồ đội tuyển Anh WorldCup 2026'
    WHEN 'WC-004' THEN 'Bộ đồ đội tuyển Brazil WorldCup 2026'
    WHEN 'WC-005' THEN 'Bộ đồ đội tuyển Bồ Đào Nha WorldCup 2026'
    WHEN 'WC-006' THEN 'Bộ đồ đội tuyển Tây Ban Nha WorldCup 2026'
    WHEN 'WC-007' THEN 'Bộ đồ đội tuyển Hàn Quốc WorldCup 2026'
    WHEN 'WC-008' THEN 'Bộ đồ đội tuyển Nhật Bản WorldCup 2026'
    WHEN 'WC-009' THEN 'Bộ đồ đội tuyển Croatia WorldCup 2026'
    WHEN 'WC-010' THEN 'Bộ đồ đội tuyển Argentina WorldCup 2026'
    WHEN 'WC-011' THEN 'Bộ đồ đội tuyển Uruguay WorldCup 2026'
    WHEN 'WC-012' THEN 'Bộ đồ đội tuyển Bỉ WorldCup 2026'
END
WHERE sku IN (
    'WC-001', 'WC-002', 'WC-003', 'WC-004', 'WC-005', 'WC-006',
    'WC-007', 'WC-008', 'WC-009', 'WC-010', 'WC-011', 'WC-012'
);
