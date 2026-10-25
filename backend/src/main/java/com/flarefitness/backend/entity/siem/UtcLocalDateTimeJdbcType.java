package com.flarefitness.backend.entity.siem;

import java.sql.Types;
import org.hibernate.type.descriptor.jdbc.LocalDateTimeJdbcType;

/** Direct Java-time IO with a standard temporal code understood by Hibernate 6 aggregate validation. */
public final class UtcLocalDateTimeJdbcType extends LocalDateTimeJdbcType {
    @Override
    public int getJdbcTypeCode() {
        return Types.TIMESTAMP;
    }
}
