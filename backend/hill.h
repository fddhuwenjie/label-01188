#pragma once
/**
 * hill.h — Hill密码 (n=3) 加密/解密
 */

#include <string>
#include <stdexcept>
#include "math_utils.h"

using std::string;

inline string hillEnc(const string& p, int k[3][3]) {
    if (!isValidUpperAlpha(p)) throw std::invalid_argument("hillEnc: input must be A-Z");
    string s = p;
    while (s.length() % 3) s += 'X';
    string r;
    r.reserve(s.length());
    for (size_t i = 0; i < s.length(); i += 3) {
        for (int row = 0; row < 3; row++) {
            int sum = 0;
            for (int col = 0; col < 3; col++)
                sum += k[row][col] * (s[i + col] - 'A');
            r += (char)(mod(sum, 26) + 'A');
        }
    }
    return r;
}

inline string hillDec(const string& c, int k[3][3]) {
    if (!isValidUpperAlpha(c)) throw std::invalid_argument("hillDec: input must be A-Z");
    if (c.length() % 3 != 0) throw std::invalid_argument("hillDec: length must be multiple of 3");
    int ki[3][3];
    if (!inv3x3(k, ki)) return "";
    string r;
    r.reserve(c.length());
    for (size_t i = 0; i < c.length(); i += 3) {
        for (int row = 0; row < 3; row++) {
            int sum = 0;
            for (int col = 0; col < 3; col++)
                sum += ki[row][col] * (c[i + col] - 'A');
            r += (char)(mod(sum, 26) + 'A');
        }
    }
    return r;
}
