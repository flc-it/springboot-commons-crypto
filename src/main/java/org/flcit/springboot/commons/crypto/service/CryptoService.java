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

package org.flcit.springboot.commons.crypto.service;

import java.security.GeneralSecurityException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.flcit.springboot.commons.core.exception.BadRequestException;
import org.flcit.springboot.commons.core.exception.ExpiredException;
import org.flcit.commons.core.util.StringUtils;
import org.flcit.springboot.commons.crypto.configuration.CryptoConfiguration;

/**
 * 
 * @since 
 * @author Florian Lestic
 */
@Service
public class CryptoService {

    private static final String CIPHER = "%s/CBC/PKCS5Padding";

    private final SecretKeySpec secretKey;
    private final String transformation;

    /**
     * @param cryptoConfiguration
     */
    @Autowired
    public CryptoService(CryptoConfiguration cryptoConfiguration) {
        this.secretKey = cryptoConfiguration.getKey();
        this.transformation = String.format(CIPHER, cryptoConfiguration.getAlgorithm());
    }

    /**
     * @param dureeValidityInMilliseconds
     * @return
     */
    public String encryptToString(long dureeValidityInMilliseconds) {
        return encryptToString(StringUtils.EMPTY, dureeValidityInMilliseconds);
    }

    /**
     * @param toEncrypt
     * @param dureeValidityInMilliseconds
     * @return
     */
    public String encryptToString(String toEncrypt, long dureeValidityInMilliseconds) {
        return encryptToString((System.currentTimeMillis() + dureeValidityInMilliseconds) + ";" + toEncrypt);
    }

    private byte[] encrypt(String toEncrypt) {
        try {
            final Cipher cipherInstance = Cipher.getInstance(this.transformation);
            cipherInstance.init(Cipher.ENCRYPT_MODE, this.secretKey);
            final byte[] iv = cipherInstance.getIV();
            final byte[] data = cipherInstance.doFinal(toEncrypt.getBytes());
            final byte[] finalData = new byte[iv.length + data.length];
            System.arraycopy(iv, 0, finalData, 0, iv.length);
            System.arraycopy(data, 0, finalData, iv.length, data.length);
            return finalData;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * @param toEncrypt
     * @return
     */
    public String encryptToString(String toEncrypt) {
        return encodeToString(encrypt(toEncrypt));
    }

    /**
     * @param toEncrypt
     * @return
     */
    public byte[] encryptToByte(String toEncrypt) {
        return encodeToByte(encrypt(toEncrypt));
    }

    private static final String encodeToString(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

    private static final byte[] encodeToByte(byte[] data) {
        return Base64.getUrlEncoder().encode(data);
    }

    /**
     * @param toDecrypt
     * @return
     */
    public String decryptWithValidity(byte[] toDecrypt) {
        return checkValidity(decrypt(toDecrypt));
    }

    /**
     * @param toDecrypt
     * @return
     */
    public String decryptWithValidity(String toDecrypt) {
        return checkValidity(decrypt(toDecrypt));
    }

    private static final String checkValidity(String decrypted) {
        final int index = decrypted.indexOf(';');
        if (index == -1) {
            throw new BadRequestException("UNABLE TO FIND VALIDITY");
        }
        if (System.currentTimeMillis() > Long.parseLong(decrypted.substring(0, index))) {
            throw new ExpiredException();
        }
        return decrypted.substring(index + 1);
    }

    private static final byte[] decode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    private static final byte[] decode(byte[] data) {
        return Base64.getUrlDecoder().decode(data);
    }

    /**
     * @param toDecrypt
     * @return
     */
    public String decrypt(String toDecrypt) {
        return new String(decryptIntern(decode(toDecrypt)));
    }

    /**
     * @param toDecrypt
     * @return
     */
    public String decrypt(byte[] toDecrypt) {
        return new String(decryptIntern(decode(toDecrypt)));
    }

    private byte[] decryptIntern(byte[] data) {
        try {
            final Cipher cipherInstance = Cipher.getInstance(this.transformation);
            cipherInstance.init(Cipher.DECRYPT_MODE, this.secretKey, new IvParameterSpec(data, 0, cipherInstance.getBlockSize()));
            return cipherInstance.doFinal(data, cipherInstance.getBlockSize(), data.length - cipherInstance.getBlockSize());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

}
