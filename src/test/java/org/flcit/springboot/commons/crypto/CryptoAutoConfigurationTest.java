/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.flcit.springboot.commons.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.core.env.MapPropertySource;

import org.flcit.springboot.commons.core.exception.BadRequestException;
import org.flcit.springboot.commons.core.exception.ExpiredException;
import org.flcit.commons.core.util.StringUtils;
import org.flcit.springboot.commons.crypto.configuration.CryptoConfiguration;
import org.flcit.springboot.commons.crypto.service.CryptoService;
import org.flcit.springboot.commons.test.util.ContextRunnerUtils;
import org.flcit.springboot.commons.test.util.PropertyTestUtils;

class CryptoAutoConfigurationTest {

    private static final String RESULT = "TEST_TEST_AZERTYUIOPQSDFGHJKLMWXCVBN";
    private static final Long VALIDITY = 60000L;

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    CommonsCryptoAutoConfiguration.class));

    @Test
    void commonsCryptoAutoConfigurationNoProperties() {
        ContextRunnerUtils.assertHasFailed(this.contextRunner);
    }

    @Test
    void commonsCryptoAutoConfigurationBeanKeyStringOk() {
        ContextRunnerUtils.assertHasSingleBean(
                this.contextRunner
                .withPropertyValues(PropertyTestUtils.getValue("crypto.", "key-string", "web-crypto-lib@test-environment")),
                CryptoConfiguration.class, CryptoService.class);

    }

    @Test
    void commonsCryptoAutoConfigurationBeanKeyOk() {
        ContextRunnerUtils.assertHasSingleBean(
                this.contextRunner
                .withInitializer((test) -> test.getEnvironment().getPropertySources().addFirst(new MapPropertySource("dynamicPropertySource", Collections.singletonMap("crypto.key", generate())))),
                CryptoConfiguration.class, CryptoService.class);
    }

    @Test
    void cryptDecryptKeyStringOk() {
        this.contextRunner
        .withInitializer((test) -> test.getEnvironment().getPropertySources().addFirst(new MapPropertySource("dynamicPropertySource", Collections.singletonMap("crypto.key", generate()))))
        .run(context -> {
            final CryptoService service = context.getBean(CryptoService.class);
            assertEquals(StringUtils.EMPTY, service.decryptWithValidity(service.encryptToString(VALIDITY)));
            assertEquals(RESULT, service.decryptWithValidity(service.encryptToString(RESULT, VALIDITY)));
            assertEquals(RESULT, service.decrypt(service.encryptToString(RESULT)));
            final String v = service.encryptToString(RESULT);
            assertThrows(BadRequestException.class, () -> service.decryptWithValidity(v));
            final String v2 = service.encryptToString(RESULT, -VALIDITY);
            assertThrows(ExpiredException.class, () -> service.decryptWithValidity(v2));
            assertEquals(RESULT, service.decrypt(service.encryptToByte(RESULT)));
            assertEquals(RESULT, service.decryptWithValidity(service.encryptToString(RESULT, VALIDITY).getBytes()));
        });
    }

    @Test
    void cryptDecryptKo() {
        this.contextRunner
        .withInitializer((test) -> test.getEnvironment().getPropertySources().addFirst(new MapPropertySource("dynamicPropertySource", Collections.singletonMap("crypto.key", generate()))))
        .run(context -> {
            final CryptoService service = context.getBean(CryptoService.class);
            try (MockedStatic<Cipher> mock = mockStatic(Cipher.class)) {
                when(Cipher.getInstance(anyString())).thenThrow(NoSuchAlgorithmException.class);
                assertThrows(IllegalStateException.class, () -> service.encryptToString(RESULT));
            }
            final String v = service.encryptToString(RESULT);
            try (MockedStatic<Cipher> mock = mockStatic(Cipher.class)) {
                when(Cipher.getInstance(anyString())).thenThrow(NoSuchAlgorithmException.class);
                assertThrows(IllegalStateException.class, () -> service.decrypt(v));
            }
        });
    }

    @Test
    void checkValidityKo() {
        this.contextRunner
        .withInitializer((test) -> test.getEnvironment().getPropertySources().addFirst(new MapPropertySource("dynamicPropertySource", Collections.singletonMap("crypto.key", generate()))))
        .run(context -> {
            final CryptoService service = context.getBean(CryptoService.class);
            assertEquals(StringUtils.EMPTY, service.decryptWithValidity(service.encryptToString(VALIDITY)));
            assertEquals(RESULT, service.decryptWithValidity(service.encryptToString(RESULT, VALIDITY)));
            assertEquals(RESULT, service.decrypt(service.encryptToString(RESULT)));
        });
    }

    private static final byte[] generate() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
