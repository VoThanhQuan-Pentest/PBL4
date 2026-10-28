package com.flarefitness.backend.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.Product;
import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.repository.ProductRepository;
import com.flarefitness.backend.repository.siem.SiemIncidentRepository;
import com.flarefitness.backend.service.siem.SiemIncidentService;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.annotation.Transactional;

/** Actual MySQL/Hibernate bindings; fixtures are isolated and rolled back. */
@SpringBootTest
@Transactional
class SqlQueryBindingIntegrationTest extends ContainerizedIntegrationTest {
    @Autowired ProductRepository products;
    @Autowired SiemIncidentRepository incidents;
    @Autowired SiemIncidentService service;

    @Test void jpqlTreatsQuotedSkuAsOneLiteralValue() {
        String value = marker() + "' OR 1=1 --";
        Product literal = product(value, marker(), "Quoted SKU fixture");
        product(marker(), marker(), "Unrelated fixture");
        assertThat(products.findBySkuIgnoreCase(value)).get().extracting(Product::getId).isEqualTo(literal.getId());
        assertThat(products.findBySkuIgnoreCase(value + "extra")).isEmpty();
    }

    @Test void derivedQueryDoesNotInterpretGroupingKeyAsSql() {
        String value = marker() + "' OR '1'='1";
        SiemIncident literal = incident(value, "Grouping fixture");
        incident(marker(), "Unrelated grouping fixture");
        assertThat(incidents.findByGroupingKey(value)).get().extracting(SiemIncident::getId).isEqualTo(literal.getId());
        assertThat(incidents.findByGroupingKey(value + "extra")).isEmpty();
    }

    @Test void nativeFilterAndCountQueriesBindQuotedCategory() {
        String value = marker() + "' OR 1=1 --";
        Product literal = product(marker(), value, "Native category fixture");
        product(marker(), marker(), "Unrelated category fixture");
        // A full page of size one exercises the native count query as well.
        var page = PageRequest.of(0, 1);
        var fulltext = products.searchProducts(null, value, null, null, null, null, 0, page);
        var fallback = products.searchProductsFallback(null, value, null, null, null, null, 0, page);
        for (var result : java.util.List.of(fulltext, fallback)) {
            assertThat(result.getTotalElements()).isEqualTo(1);
            assertThat(result.getContent()).extracting(Product::getId).containsExactly(literal.getId());
        }
    }

    @Test void nativeLikeSearchRetainsQuotedDataWithoutBroadeningResults() {
        String prefix = marker();
        String value = prefix + "' UNION SELECT secret --";
        Product literal = product(marker(), marker(), value);
        product(marker(), marker(), prefix + " benign control");
        var result = products.searchProductsFallback("%" + value + "%", null, null, null,
                null, null, 0, PageRequest.of(0, 1));
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getContent()).extracting(Product::getId).containsExactly(literal.getId());
    }

    @Test void criteriaSearchBindsQuotedTermForBothSortOrders() {
        String prefix = marker();
        String value = prefix + "' OR 1=1 --";
        SiemIncident literal = incident(marker(), value);
        incident(marker(), prefix + " benign control");
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        for (var sort : SiemDtos.IncidentSort.values()) {
            var result = service.findIncidents(0, 1, null, null, null,
                    SiemDtos.IncidentScope.ALL, sort, value, now.minusHours(1), now.plusHours(1));
            assertThat(result.totalElements()).isEqualTo(1);
            assertThat(result.content()).extracting(SiemDtos.Incident::id).containsExactly(literal.getId());
        }
        var absent = service.findIncidents(0, 1, null, null, null, SiemDtos.IncidentScope.ALL,
                SiemDtos.IncidentSort.LATEST, value + "extra", now.minusHours(1), now.plusHours(1));
        assertThat(absent.content()).isEmpty();
    }

    private Product product(String sku, String category, String title) {
        Product p = new Product();
        p.setId(marker()); p.setSku(sku); p.setTenSanPham(title); p.setDanhMuc(category);
        p.setGiaNhap(BigDecimal.ONE); p.setGiaBan(BigDecimal.TEN); p.setTonKho(1);
        p.setTrangThai("ACTIVE"); p.setDeleted(false); p.setCreatedAt(LocalDateTime.now(ZoneOffset.UTC));
        return products.saveAndFlush(p);
    }

    private SiemIncident incident(String grouping, String title) {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        SiemIncident i = new SiemIncident();
        i.setId(marker()); i.setGroupingKey(grouping); i.setServiceId("asvs-sql-fixture");
        i.setRuleId("ASVS_SQL_BINDING"); i.setSourceIp("192.0.2.45");
        i.setBucketStart(now.withSecond(0).withNano(0)); i.setTitle(title);
        i.setSourceSeverity("medium"); i.setScore(50); i.setSeverity(IncidentSeverity.MEDIUM);
        i.setClassification(IncidentClassification.INVESTIGATE); i.setClassificationReason("Synthetic SQL binding fixture");
        i.setMissingData(false); i.setStatus(IncidentStatus.NEW); i.setConclusion(IncidentConclusion.UNREVIEWED);
        i.setManualInvestigateOverride(false); i.setAlertCount(1); i.setDistinctRuleCount(1);
        i.setFirstSeen(now); i.setLastSeen(now); i.setCreatedAt(now); i.setUpdatedAt(now);
        return incidents.saveAndFlush(i);
    }

    private static String marker() { return "sql" + UUID.randomUUID().toString().replace("-", ""); }
}
