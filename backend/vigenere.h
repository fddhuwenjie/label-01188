#pragma once
/**
 * vigenere.h — 维吉尼亚密码加密/解密
 */

#include <string>
#include <stdexcept>
#include "math_utils.h"

using std::string;

inline string vigEnc(const string& p, const string& k) {
    if (k.empty()) throw std::invalid_argument("vigEnc: key must not be empty");
    if (!isValidUpperAlpha(k)) throw std::invalid_argument("vigEnc: key must be A-Z");
    if (!isValidUpperAlpha(p)) throw std::invalid_argument("vigEnc: plaintext must be A-Z");
    string r;
    r.reserve(p.length());
    for (size_t i = 0; i < p.length(); i++)
        r += (char)(mod((p[i] - 'A') + (k[i % k.length()] - 'A'), 26) + 'A');
    return r;
}

inline string vigDec(const string& c, const string& k) {
    if (k.empty()) throw std::invalid_argument("vigDec: key must not be empty");
    if (!isValidUpperAlpha(k)) throw std::invalid_argument("vigDec: key must be A-Z");
    if (!isValidUpperAlpha(c)) throw std::invalid_argument("vigDec: ciphertext must be A-Z");
    string r;
    r.reserve(c.length());
    for (size_t i = 0; i < c.length(); i++)
        r += (char)(mod((c[i] - 'A') - (k[i % k.length()] - 'A'), 26) + 'A');
    return r;
}
