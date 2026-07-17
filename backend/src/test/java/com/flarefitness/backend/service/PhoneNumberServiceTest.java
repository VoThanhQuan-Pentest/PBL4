package com.flarefitness.backend.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.repository.CustomerRepository;
import java.util.Collection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PhoneNumberServiceTest {

    @Mock
    private CustomerRepository customerRepository;

    private PhoneNumberService phoneNumberService;

    @BeforeEach
    void setUp() {
        phoneNumberService = new PhoneNumberService(customerRepository);
    }

    @Test
    void normalizesVietnamCountryCodeToLocalFormat() {
        assertThat(phoneNumberService.normalize("+84905138097")).isEqualTo("0905138097");
    }

    @Test
    void rejectsEquivalentPhoneNumberDuringRegistration() {
        when(customerRepository.existsActiveBySdtIn(argThat(this::containsEquivalentFormats))).thenReturn(true);

        assertThatThrownBy(() -> phoneNumberService.requireAvailable("+84905138097", null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("So dien thoai da duoc su dung");
    }

    @Test
    void allowsCurrentCustomerToKeepOwnPhoneNumber() {
        when(customerRepository.existsActiveBySdtInAndUserIdNot(
                argThat(this::containsEquivalentFormats),
                eq("user-customer-1")
        )).thenReturn(false);

        assertThat(phoneNumberService.requireAvailable("+84905138097", "user-customer-1"))
                .isEqualTo("0905138097");
    }

    private boolean containsEquivalentFormats(Collection<String> values) {
        return values.contains("0905138097") && values.contains("+84905138097");
    }
}
