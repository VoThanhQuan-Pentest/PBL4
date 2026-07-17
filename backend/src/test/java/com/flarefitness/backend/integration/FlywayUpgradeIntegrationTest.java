package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

class FlywayUpgradeIntegrationTest {

    private static final DockerImageName MYSQL_IMAGE = DockerImageName
            .parse("mysql:8.4@sha256:c831a0f11348d402b43d77453e17d770be2eef356615a2823fe0f5a0d6c8b9af")
            .asCompatibleSubstituteFor("mysql");

    @Test
    void upgradesAnOldSnapshotWithoutLosingIdentityAndRepairsWorldCupText() throws Exception {
        MySQLContainer<?> mysql = new MySQLContainer<>(MYSQL_IMAGE)
                .withDatabaseName("flare_fitness")
                .withUsername("flare")
                .withPassword("flare-test-password");
        mysql.start();
        try {
            Flyway snapshotFlyway = flyway(mysql, "3");
            snapshotFlyway.migrate();
            seedVersionThreeSnapshot(mysql);

            // Stop just before V11 so a real pre-link redemption row can be
            // preserved by the nullable compatibility column added in V11.
            Flyway versionTenFlyway = flyway(mysql, "10");
            versionTenFlyway.migrate();
            seedVersionTenVoucherRedemption(mysql);

            Flyway latestFlyway = flyway(mysql, null);
            latestFlyway.migrate();

            assertThat(latestFlyway.info().current().getVersion().getVersion()).isEqualTo("11");
            try (Connection connection = connection(mysql)) {
                assertThat(readString(connection,
                        "SELECT ten_san_pham FROM tbl_san_pham WHERE sku = 'WC-001'"))
                        .isEqualTo("Bộ đồ đội tuyển Đức WorldCup 2026");
                assertThat(readString(connection,
                        "SELECT user_id FROM tbl_khach_hang WHERE id = 'legacy-customer'"))
                        .isEqualTo("legacy-user");
                assertThat(readString(connection,
                        "SELECT id FROM tbl_san_pham WHERE id = 'legacy-worldcup-product'"))
                        .isEqualTo("legacy-worldcup-product");
                assertThat(readString(connection,
                        "SELECT password FROM tbl_nguoi_dung WHERE id = 'legacy-plaintext-user'"))
                        .startsWith("{reset-required}")
                        .isNotEqualTo("plain-text-password");
                assertThat(readString(connection,
                        "SELECT reason FROM tbl_tai_khoan_can_dat_lai_mat_khau "
                                + "WHERE user_id = 'legacy-plaintext-user'"))
                        .isEqualTo("LEGACY_NON_BCRYPT_PASSWORD");
                assertThat(readString(connection,
                        "SELECT index_name FROM information_schema.statistics "
                                + "WHERE table_schema = DATABASE() AND table_name = 'tbl_don_hang' "
                                + "AND index_name = 'idx_tbl_don_hang_active_cursor'"))
                        .isEqualTo("idx_tbl_don_hang_active_cursor");
                assertThat(readString(connection,
                        "SELECT constraint_name FROM information_schema.referential_constraints "
                                + "WHERE constraint_schema = DATABASE() "
                                + "AND table_name = 'tbl_su_dung_ma_giam_gia' "
                                + "AND constraint_name = 'fk_voucher_redemption_order'"))
                        .isEqualTo("fk_voucher_redemption_order");
                assertThat(readString(connection,
                        "SELECT order_id FROM tbl_su_dung_ma_giam_gia WHERE id = 'legacy-redemption'"))
                        .isNull();
            }
            assertThat(latestFlyway.migrate().migrationsExecuted).isZero();
        } finally {
            mysql.stop();
        }
    }

    private Flyway flyway(MySQLContainer<?> mysql, String target) {
        var configuration = Flyway.configure()
                .dataSource(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword())
                .locations("classpath:db/migration");
        if (target != null) {
            configuration.target(target);
        }
        return configuration.load();
    }

    private void seedVersionThreeSnapshot(MySQLContainer<?> mysql) throws Exception {
        try (Connection connection = connection(mysql)) {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_nguoi_dung
                        (id, username, password, role, ho_ten, email, trang_thai, is_deleted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "legacy-user");
                statement.setString(2, "legacy_customer");
                statement.setString(3, "$2a$12$Z8xXRjkmASDQSZXYwYEwZOqBzW7WSTl4YpJrB2O2A1s2dWmQWdd5S");
                statement.setString(4, "CUSTOMER");
                statement.setString(5, "Legacy Customer");
                statement.setString(6, "legacy@example.test");
                statement.setString(7, "Hoat dong");
                statement.setBoolean(8, false);
                statement.executeUpdate();
            }

            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_nguoi_dung
                        (id, username, password, role, ho_ten, email, trang_thai, is_deleted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "legacy-plaintext-user");
                statement.setString(2, "legacy_plaintext_customer");
                statement.setString(3, "plain-text-password");
                statement.setString(4, "CUSTOMER");
                statement.setString(5, "Legacy Plaintext Customer");
                statement.setString(6, "legacy-plaintext@example.test");
                statement.setString(7, "Hoat dong");
                statement.setBoolean(8, false);
                statement.executeUpdate();
            }

            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_khach_hang
                        (id, user_id, ten_khach, sdt, email, is_deleted)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "legacy-customer");
                statement.setString(2, "legacy-user");
                statement.setString(3, "Legacy Customer");
                statement.setString(4, "0900000001");
                statement.setString(5, "legacy@example.test");
                statement.setBoolean(6, false);
                statement.executeUpdate();
            }

            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_san_pham
                        (id, ten_san_pham, sku, danh_muc, thuong_hieu, gia_nhap, gia_ban,
                         ton_kho, trang_thai, is_deleted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "legacy-worldcup-product");
                statement.setString(2, "Broken WorldCup title");
                statement.setString(3, "WC-001");
                statement.setString(4, "Bóng đá");
                statement.setString(5, "Flare");
                statement.setBigDecimal(6, java.math.BigDecimal.valueOf(100_000));
                statement.setBigDecimal(7, java.math.BigDecimal.valueOf(200_000));
                statement.setInt(8, 10);
                statement.setString(9, "Đang bán");
                statement.setBoolean(10, false);
                statement.executeUpdate();
            }
        }
    }

    private void seedVersionTenVoucherRedemption(MySQLContainer<?> mysql) throws Exception {
        try (Connection connection = connection(mysql)) {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_ma_giam_gia
                        (ma, nhan, ty_le_giam, gia_tri_don_toi_thieu, giam_toi_da, trang_thai)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, "LEGACY10");
                statement.setString(2, "Legacy voucher");
                statement.setBigDecimal(3, java.math.BigDecimal.valueOf(0.10));
                statement.setBigDecimal(4, java.math.BigDecimal.ZERO);
                statement.setBigDecimal(5, java.math.BigDecimal.valueOf(100_000));
                statement.setString(6, "ACTIVE");
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_phan_bo_ma_giam_gia
                        (id, user_id, voucher_code, so_luong, so_luong_da_dung, trang_thai, ngay_cap)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """)) {
                statement.setString(1, "legacy-voucher-assignment");
                statement.setString(2, "legacy-user");
                statement.setString(3, "LEGACY10");
                statement.setInt(4, 1);
                statement.setInt(5, 1);
                statement.setString(6, "ACTIVE");
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO tbl_su_dung_ma_giam_gia
                        (id, assignment_id, user_id, voucher_code, subtotal, so_tien_giam, ngay_su_dung)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """)) {
                statement.setString(1, "legacy-redemption");
                statement.setString(2, "legacy-voucher-assignment");
                statement.setString(3, "legacy-user");
                statement.setString(4, "LEGACY10");
                statement.setBigDecimal(5, java.math.BigDecimal.valueOf(500_000));
                statement.setBigDecimal(6, java.math.BigDecimal.valueOf(50_000));
                statement.executeUpdate();
            }
        }
    }

    private Connection connection(MySQLContainer<?> mysql) throws Exception {
        return DriverManager.getConnection(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword());
    }

    private String readString(Connection connection, String sql) throws Exception {
        try (PreparedStatement statement = connection.prepareStatement(sql);
                ResultSet result = statement.executeQuery()) {
            assertThat(result.next()).isTrue();
            return result.getString(1);
        }
    }
}
