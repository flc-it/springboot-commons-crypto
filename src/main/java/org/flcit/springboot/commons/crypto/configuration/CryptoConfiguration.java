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

import java.security.GeneralSecurityException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

/**
 * 
 * @since 
 * @author Florian Lestic
 */
@ConfigurationProperties("crypto")
public class CryptoConfiguration {

    private String algorithm = "AES";
    private int length = 256;
    private byte[] key;
    private String keyString;

    /**
     * @return
     */
    public String getAlgorithm() {
        return algorithm;
    }
    /**
     * @param algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
    /**
     * @param length
     */
    public void setLength(int length) {
        this.length = length;
    }
    /**
     * @param key
     */
    public void setKey(byte[] key) {
        this.key = key;
    }
    /**
     * @param keyString
     */
    public void setKeyString(String keyString) {
        this.keyString = keyString;
    }
    /**
     * @return
     */
    public SecretKeySpec getKey() {
        if (!ObjectUtils.isEmpty(key)) {
            return getKey(algorithm, key);
        }
        if (StringUtils.hasLength(keyString)) {
            return getKey(algorithm, length, keyString);
        }
        throw new IllegalStateException("No key is Provided, please provide a crypto.key or crypto.key-string value");
    }
    private static final SecretKeySpec getKey(final String algorithm, final int length, final String key) {
        try {
            return getKey(algorithm,
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(
                            new PBEKeySpec(null, key.getBytes(), 65536, length)
                            ).getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    private static final SecretKeySpec getKey(final String algorithm, final byte[] key) {
        return new SecretKeySpec(key, algorithm);
    }
}
