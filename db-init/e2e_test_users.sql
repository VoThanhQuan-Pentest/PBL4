USE flare_fitness;

INSERT INTO tbl_nguoi_dung (
    id, username, password, role, ho_ten, email, avatar_url, trang_thai,
    lan_dang_nhap_cuoi, ngay_tao, ngay_cap_nhat, is_deleted
)
VALUES
    ('e2e-admin', 'e2e_admin', '$2y$10$mS3g/3mOmbeQM59Eg05TQ.Zqk57L.6Ssuh2vcBnfvDC1RZ3r5Aq56', 'admin', 'E2E Admin', 'admin.e2e@flarefitness.test', NULL, 'Đang hoạt động', NULL, NOW(), NOW(), 0),
    ('e2e-staff', 'e2e_staff', '$2y$10$PY7R8xzEFG7Q1ZIjiR2x9u.kVCDFATmREVAyc8IFJDriAr8/tAYsm', 'staff', 'E2E Staff', 'staff.e2e@flarefitness.test', NULL, 'Đang hoạt động', NULL, NOW(), NOW(), 0),
    ('e2e-customer', 'e2e_customer', '$2y$10$.YoZkjbqz4A7guoe44j0Vu5SRtE8SfJ31//yfin1Zp8Wx.hYbe3yi', 'customer', 'E2E Customer', 'customer.e2e@flarefitness.test', NULL, 'Đang hoạt động', NULL, NOW(), NOW(), 0)
ON DUPLICATE KEY UPDATE
    password = VALUES(password),
    role = VALUES(role),
    trang_thai = VALUES(trang_thai),
    is_deleted = VALUES(is_deleted);
