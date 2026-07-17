package com.flarefitness.backend.service;

import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.CustomerRepository;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class PhoneNumberService {

    private final CustomerRepository customerRepository;

    public PhoneNumberService(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    public String normalize(String phoneNumber) {
        String normalized = String.valueOf(phoneNumber == null ? "" : phoneNumber)
                .trim()
                .replaceAll("[\\s.()-]", "");
        if (normalized.startsWith("+84")) {
            return "0" + normalized.substring(3);
        }
        return normalized;
    }

    public String requireAvailable(String phoneNumber, String currentUserId) {
        String normalized = normalize(phoneNumber);
        if (normalized.isBlank()) {
            return normalized;
        }

        Set<String> equivalentNumbers = new LinkedHashSet<>();
        equivalentNumbers.add(normalized);
        if (normalized.startsWith("0")) {
            equivalentNumbers.add("+84" + normalized.substring(1));
        }

        boolean exists = currentUserId == null || currentUserId.isBlank()
                ? customerRepository.existsActiveBySdtIn(equivalentNumbers)
                : customerRepository.existsActiveBySdtInAndUserIdNot(equivalentNumbers, currentUserId);
        if (exists) {
            throw new BadRequestException("So dien thoai da duoc su dung boi tai khoan khac.");
        }
        return normalized;
    }
}
