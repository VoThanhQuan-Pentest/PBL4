package com.flarefitness.backend.service.siem;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Purpose-specific pseudonymization; absence of its private key means missing coverage, never a plain hash. */
@Component
public class SiemAuthTelemetry {
    public static final String REQUEST_ID=SiemAuthTelemetry.class.getName()+".REQUEST_ID";
    private static final String TARGET=SiemAuthTelemetry.class.getName()+".TARGET";
    public record Fingerprint(String value,String keyId) { }
    private final Path keyFile;
    public SiemAuthTelemetry(@Value("${siem.auth.fingerprint-key-file:/run/siem-auth/fingerprint.key}") String file){keyFile=Path.of(file);}
    public void loginTarget(String normalizedUsername) {
        if(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes request)
            request.getRequest().setAttribute(TARGET,fingerprint(normalizedUsername));
    }
    public Fingerprint fingerprint(String normalizedUsername) {
        if(normalizedUsername==null||normalizedUsername.length()>100)return null;
        return keyed("flare-auth-target-v1",normalizedUsername.trim().toLowerCase(Locale.ROOT));
    }
    public String keyId(){var value=keyed("flare-auth-key-id-v1","");return value==null?null:value.keyId();}
    public Fingerprint sessionFingerprint(String verifiedToken) {
        if(verifiedToken==null||verifiedToken.length()>8192)return null;
        return keyed("flare-auth-session-v1",verifiedToken);
    }
    private Fingerprint keyed(String purpose,String value) {
        try {
            if(!Files.isRegularFile(keyFile,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(keyFile)||Files.size(keyFile)!=32)return null;
            for(Path parent=keyFile.toAbsolutePath();parent!=null;parent=parent.getParent())if(Files.isSymbolicLink(parent))return null;
            var permissions=Files.getPosixFilePermissions(keyFile);
            if(permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ)||permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE)||permissions.contains(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE))return null;
            byte[] key;
            try(var input=Files.newInputStream(keyFile,LinkOption.NOFOLLOW_LINKS)){key=input.readNBytes(33);}
            if(key.length!=32)return null;
            Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));
            String result=HexFormat.of().formatHex(mac.doFinal((purpose+"\0"+value).getBytes(StandardCharsets.UTF_8)));
            String keyId=HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(key)).substring(0,16);
            java.util.Arrays.fill(key,(byte)0);return new Fingerprint(result,keyId);
        }catch(Exception unavailable){return null;}
    }
    public static void attach(com.flarefitness.backend.entity.siem.SiemSecurityEvent event) {
        if(!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes))return;
        var request=attributes.getRequest();Object id=request.getAttribute(REQUEST_ID);
        if(id instanceof String value)event.setAuthRequestId(value);
        if(request.getAttribute(TARGET) instanceof Fingerprint value){event.setAuthTargetFingerprint(value.value());event.setFingerprintKeyId(value.keyId());}
    }
}
