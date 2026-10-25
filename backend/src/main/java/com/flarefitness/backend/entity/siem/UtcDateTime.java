package com.flarefitness.backend.entity.siem;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.hibernate.annotations.JdbcType;

/**
 * SIEM operational DATETIME columns contain UTC clock values. Bind/extract
 * Java time directly, without the legacy business module's JDBC calendar shift.
 * Shared BaseEntity.ngay_tao retains its existing business mapping.
 */
@Target({ElementType.FIELD, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@JdbcType(UtcLocalDateTimeJdbcType.class)
public @interface UtcDateTime { }
