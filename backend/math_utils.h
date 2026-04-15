#pragma once
/**
 * math_utils.h — 模26数学工具函数
 */

#include <algorithm>
#include <stdexcept>
#include <string>

inline int mod(int a, int m) {
    if (m <= 0) throw std::invalid_argument("mod: modulus must be positive");
    return ((a % m) + m) % m;
}

inline int gcd(int a, int b) {
    a = std::abs(a); b = std::abs(b);
    while (b) { int t = b; b = a % b; a = t; }
    return a;
}

inline int modInverse(int a, int m) {
    a = mod(a, m);
    for (int x = 1; x < m; x++)
        if (mod(a * x, m) == 1) return x;
    return -1;
}

inline int det3x3(int m[3][3]) {
    int d = m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
          - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
          + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
    return mod(d, 26);
}

inline bool inv3x3(int m[3][3], int inv[3][3]) {
    int d = det3x3(m);
    if (gcd(d, 26) != 1) return false;
    int di = modInverse(d, 26);
    if (di == -1) return false;

    int adj[3][3];
    adj[0][0] =  (m[1][1] * m[2][2] - m[1][2] * m[2][1]);
    adj[0][1] = -(m[0][1] * m[2][2] - m[0][2] * m[2][1]);
    adj[0][2] =  (m[0][1] * m[1][2] - m[0][2] * m[1][1]);
    adj[1][0] = -(m[1][0] * m[2][2] - m[1][2] * m[2][0]);
    adj[1][1] =  (m[0][0] * m[2][2] - m[0][2] * m[2][0]);
    adj[1][2] = -(m[0][0] * m[1][2] - m[0][2] * m[1][0]);
    adj[2][0] =  (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
    adj[2][1] = -(m[0][0] * m[2][1] - m[0][1] * m[2][0]);
    adj[2][2] =  (m[0][0] * m[1][1] - m[0][1] * m[1][0]);

    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            inv[i][j] = mod(adj[i][j] * di, 26);
    return true;
}

/** 验证字符串是否全为大写字母 A-Z */
inline bool isValidUpperAlpha(const std::string& s) {
    for (char c : s)
        if (c < 'A' || c > 'Z') return false;
    return true;
}
