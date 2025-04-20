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

package org.flcit.springboot.commons.crypto.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKeyFactory;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class CryptoConfigurationTest {

    @Test
    void cyptoConfigurationOk() {
        final CryptoConfiguration config = new CryptoConfiguration();
        config.setAlgorithm("ALGO");
        config.setLength(128);
        assertEquals("ALGO", config.getAlgorithm());
    }

    @Test
    void getKeyKo() throws NoSuchAlgorithmException {
        try (MockedStatic<SecretKeyFactory> mock = mockStatic(SecretKeyFactory.class)) {
            when(SecretKeyFactory.getInstance(anyString())).thenThrow(NoSuchAlgorithmException.class);
            final CryptoConfiguration config = new CryptoConfiguration();
            config.setKeyString("jhsdjfhddddddddddddddddddddddddd");
            assertThrows(IllegalStateException.class, () -> config.getKey());
        }
    }

}
