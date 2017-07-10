
/**
 * Copyright (C) 2017 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <DonglesInterface.h>
#include <virgil/crypto_tiny.h>
#include <virgil/converters/converters_tiny.h>
#include <externals/base64.h>

DonglesInterface & DonglesInterface::instance() {
    static DonglesInterface _instance;
    return _instance;
}

DonglesInterface::DonglesInterface() {
    if (!crypto_tiny_init()) {
        std::runtime_error("Can't get access to dongle.");
    }
}

std::vector<uint8_t> DonglesInterface::publicKey() {
    uint8_t * ownKey;
    std::vector<uint8_t> res;
    size_t resSz = 1024;

    res.resize(resSz);

    if (!crypto_tiny_own_public_key(&ownKey)
            || !tiny_pubkey_to_virgil(ownKey, res.data(), &resSz)) {
        std::runtime_error("Can't get own public key.");
    }

    res.resize(resSz);

    return res;
}

std::string DonglesInterface::publicKeyBase64() {
    const auto binKey(publicKey());
    const size_t base64Sz = Base64::EncodedLength(binKey.size());
    char base64[base64Sz + 1];
    if (!Base64::Encode(reinterpret_cast<const char *>(binKey.data()), binKey.size(),
                        base64, base64Sz)) {
        std::runtime_error("Can't do Base64 encoding.");
    }
    base64[base64Sz] = 0x00;
    return std::string(base64);
}