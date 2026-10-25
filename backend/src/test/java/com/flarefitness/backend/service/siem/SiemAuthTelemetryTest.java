package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SiemAuthTelemetryTest {
    @TempDir Path directory;
    @Test void keyedFingerprintIsStableNormalizedAndCannotFallBackToPlainHash()throws Exception {
        Path key=directory.resolve("fingerprint.key");var service=new SiemAuthTelemetry(key.toString());
        assertThat(service.fingerprint("customer")).isNull();
        Files.write(key,new byte[32]);Files.setPosixFilePermissions(key,PosixFilePermissions.fromString("rw-------"));
        var first=service.fingerprint(" Customer ");assertThat(first.value()).hasSize(64);assertThat(first).isEqualTo(service.fingerprint("customer"));
        byte[] second=new byte[32];second[0]=1;Files.write(key,second);assertThat(service.fingerprint("customer").value()).isNotEqualTo(first.value());
        Files.setPosixFilePermissions(key,PosixFilePermissions.fromString("rw-r--r--"));assertThat(service.fingerprint("customer")).isNull();
    }
}
