#pragma once
/**
 * cracker.h — 破解策略模块
 *
 * 破解流程：
 *   步骤1 — 逆列置换：枚举列排列密钥
 *   步骤2 — 在 C2 上做卡西斯基/弗里德曼试验确定密钥长度 m
 *   步骤3 — 在 C2 上频数分析推导维吉尼亚密钥
 *   步骤4 — Hill 已知明文攻击恢复密钥矩阵，验证解密结果
 *
 * 注意：列置换密钥就是维吉尼亚密钥（题面要求两者相同）。
 */

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include <cmath>
#include <numeric>
#include <functional>

#include "math_utils.h"
#include "hill.h"
#include "vigenere.h"
#include "columnar.h"
#include "analysis.h"

using namespace std;

struct CrackConfig {
    string ciphertext;
    string knownPlain;
    string knownCipherHead;
    int hillRow1[3] = {11, 2, 19};
    int maxKeyLen = 6;
    int minKeyLen = 2;
};

struct CrackResult {
    bool success = false;
    string vigKey;
    string c2;
    int m = 0;
    string plaintext;
    int hillKey[3][3] = {};
    vector<int> combo;
    string freqKey;
};

/** 预计算所有可逆的明文块组合（3块一组） */
inline vector<vector<int>> findInvertibleCombos(const string& padPlain) {
    vector<vector<int>> valid;
    int n = padPlain.length() / 3;
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            for (int k = j + 1; k < n; k++) {
                int P[3][3], blks[3] = {i, j, k};
                for (int idx = 0; idx < 3; idx++)
                    for (int r = 0; r < 3; r++)
                        P[r][idx] = padPlain[blks[idx]*3+r] - 'A';
                if (gcd(det3x3(P), 26) == 1)
                    valid.push_back({i, j, k});
            }
    return valid;
}

/** K = C * P^{-1} (mod 26)，验证第一行匹配 */
inline bool tryRecoverHillKey(const string& c1, const string& padPlain,
                              int b0, int b1, int b2,
                              const int expectedRow1[3],
                              int hillKey[3][3]) {
    int P[3][3], C[3][3], blks[3] = {b0, b1, b2};
    for (int idx = 0; idx < 3; idx++) {
        int blk = blks[idx];
        if (blk*3+2 >= (int)padPlain.length() || blk*3+2 >= (int)c1.length())
            return false;
        for (int i = 0; i < 3; i++) {
            P[i][idx] = padPlain[blk*3+i] - 'A';
            C[i][idx] = c1[blk*3+i] - 'A';
        }
    }
    if (gcd(det3x3(P), 26) != 1) return false;
    int Pinv[3][3];
    if (!inv3x3(P, Pinv)) return false;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++) {
            int s = 0;
            for (int k = 0; k < 3; k++) s += C[i][k] * Pinv[k][j];
            hillKey[i][j] = mod(s, 26);
        }
    for (int j = 0; j < 3; j++)
        if (hillKey[0][j] != expectedRow1[j]) return false;
    return gcd(det3x3(hillKey), 26) == 1;
}

/** 完整加密流程（验证用） */
inline string doEncrypt(const string& plain, int hillKey[3][3],
                        const string& key) {
    return colEnc(vigEnc(hillEnc(plain, hillKey), key), key);
}

/** 邻域搜索：频数分析密钥的 ±2 偏移候选 */
inline vector<string> generateNeighborKeys(const string& freqKey, int m) {
    vector<string> candidates;
    set<char> cs(freqKey.begin(), freqKey.end());
    if ((int)cs.size() == m)
        candidates.push_back(freqKey);
    for (int pos = 0; pos < m; pos++) {
        for (int delta = -2; delta <= 2; delta++) {
            if (delta == 0) continue;
            string variant = freqKey;
            variant[pos] = (char)('A' + mod((freqKey[pos]-'A') + delta, 26));
            set<char> vs(variant.begin(), variant.end());
            if ((int)vs.size() == m)
                candidates.push_back(variant);
        }
    }
    for (int p1 = 0; p1 < m; p1++) {
        for (int p2 = p1+1; p2 < m; p2++) {
            for (int d1 = -2; d1 <= 2; d1++) {
                if (d1 == 0) continue;
                for (int d2 = -2; d2 <= 2; d2++) {
                    if (d2 == 0) continue;
                    string variant = freqKey;
                    variant[p1] = (char)('A' + mod((freqKey[p1]-'A') + d1, 26));
                    variant[p2] = (char)('A' + mod((freqKey[p2]-'A') + d2, 26));
                    set<char> vs(variant.begin(), variant.end());
                    if ((int)vs.size() == m)
                        candidates.push_back(variant);
                }
            }
        }
    }
    sort(candidates.begin(), candidates.end());
    candidates.erase(unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}

/** 对给定密钥尝试完整解密验证 */
inline bool tryFullDecrypt(const CrackConfig& cfg,
                           const string& key,
                           const string& padPlain,
                           const vector<vector<int>>& validCombos,
                           CrackResult& result) {
    string c2 = colDec(cfg.ciphertext, key);
    string c1 = vigDec(c2, key);

    for (auto& combo : validCombos) {
        int hk[3][3];
        if (!tryRecoverHillKey(c1, padPlain, combo[0], combo[1], combo[2],
                               cfg.hillRow1, hk))
            continue;
        string dec = hillDec(c1, hk);
        if (dec.empty()) continue;
        if (dec.substr(0, cfg.knownPlain.length()) != cfg.knownPlain) continue;

        string reEnc = doEncrypt(dec, hk, key);
        if (reEnc != cfg.ciphertext) continue;
        if (!cfg.knownCipherHead.empty()) {
            string reEncHead = reEnc.substr(0, cfg.knownCipherHead.length());
            if (reEncHead != cfg.knownCipherHead) continue;
        }

        result.success = true;
        result.vigKey = key;
        result.c2 = c2;
        result.m = key.length();
        result.plaintext = dec;
        for (int i = 0; i < 3; i++)
            for (int j = 0; j < 3; j++)
                result.hillKey[i][j] = hk[i][j];
        result.combo = combo;
        return true;
    }
    return false;
}

/** 输出破解结果 */
inline void printResult(const CrackConfig& cfg, const CrackResult& res) {
    cout << "\n========================================\n";
    cout << "  密码分析过程\n";
    cout << "========================================\n\n";

    cout << "[步骤1] 逆列置换:\n";
    cout << "    密钥(列置换=维吉尼亚): " << res.vigKey << "\n";
    cout << "    逆列置换后 C2 = " << res.c2 << "\n\n";

    cout << "[步骤2] 在 C2 上验证密钥长度 (卡西斯基 + 弗里德曼):\n";
    auto kR = kasiskiExamination(res.c2);
    if (kR.empty()) cout << "    卡西斯基: 未找到明显重复模式\n";
    else for (int kl : kR) cout << "    卡西斯基候选: " << kl << "\n";
    auto fR = friedmanTest(res.c2, 6);
    for (auto& fp : fR)
        cout << "    弗里德曼 m=" << fp.first << ": IC=" << fp.second
             << (abs(fp.second - 0.067) < 0.015 ? " (接近英文)" : "") << "\n";
    cout << "    → 确定密钥长度 m = " << res.m << "\n\n";

    cout << "[步骤3] 频数分析推导维吉尼亚密钥 (在 C2 上):\n";
    cout << "    频数分析推导结果: " << res.freqKey << "\n";
    cout << "    最终确定密钥:     " << res.vigKey << "\n\n";

    cout << "[步骤4] Hill密钥矩阵恢复 (已知明文攻击):\n";
    cout << "    使用块组合: " << res.combo[0] << "," << res.combo[1] << "," << res.combo[2] << "\n";
    cout << "    Hill密钥矩阵 A:\n";
    for (int i = 0; i < 3; i++)
        cout << "      [" << res.hillKey[i][0] << ", " << res.hillKey[i][1]
             << ", " << res.hillKey[i][2] << "]\n";

    int hkCopy[3][3];
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            hkCopy[i][j] = res.hillKey[i][j];
    int hkInv[3][3];
    if (inv3x3(hkCopy, hkInv)) {
        cout << "    模26逆矩阵 A⁻¹:\n";
        for (int i = 0; i < 3; i++)
            cout << "      [" << hkInv[i][0] << ", " << hkInv[i][1]
                 << ", " << hkInv[i][2] << "]\n";
        int d = det3x3(hkCopy);
        cout << "    det(A) = " << d << " (mod 26), det(A)⁻¹ = " << modInverse(d, 26) << "\n";
    }

    string c1 = vigDec(res.c2, res.vigKey);

    cout << "\n========================================\n";
    cout << "  破解成功！\n";
    cout << "========================================\n\n";
    cout << "[+] 密钥(列置换=维吉尼亚): " << res.vigKey << "\n";
    cout << "[+] C1 (Hill加密后):       " << c1 << "\n";
    cout << "[+] C2 (维吉尼亚加密后):   " << res.c2 << "\n";

    string fp = res.plaintext;
    while (!fp.empty() && fp.back() == 'X') fp.pop_back();
    cout << "[+] 明文(含填充): " << res.plaintext << "\n";
    cout << "[+] 明文(去填充): " << fp << "\n\n";
    cout << "[+] 验证: 重新加密 == 密文 ✓\n";
    cout << "[+] 验证: 密文前" << cfg.knownCipherHead.length()
         << "字符匹配 ✓\n";
}

/** 主破解函数 */
inline void crack(const CrackConfig& cfg) {
    cout << "========================================\n";
    cout << "  古典密码三层加密破解程序\n";
    cout << "========================================\n\n";

    cout << "[*] 最终密文: " << cfg.ciphertext << "\n";
    cout << "[*] 密文长度: " << cfg.ciphertext.length() << "\n";
    cout << "[*] 已知明文前" << cfg.knownPlain.length() << "字符: " << cfg.knownPlain << "\n";
    cout << "[*] 对应密文前" << cfg.knownCipherHead.length() << "字符: " << cfg.knownCipherHead << "\n\n";

    string padPlain = cfg.knownPlain;
    while (padPlain.length() % 3) padPlain += 'X';
    cout << "[*] 填充后明文: " << padPlain
         << " (长度=" << padPlain.length() << ")\n\n";

    auto validCombos = findInvertibleCombos(padPlain);
    cout << "[*] 可逆块组合数: " << validCombos.size() << "\n\n";

    // 候选密钥长度: 2~maxKeyLen（列置换支持非整除长度）
    vector<int> candidateMs;
    for (int m = cfg.minKeyLen; m <= cfg.maxKeyLen; m++)
        candidateMs.push_back(m);
    cout << "[*] 候选密钥长度: ";
    for (int m : candidateMs) cout << m << " ";
    cout << "\n\n";

    for (int m : candidateMs) {
        cout << "========================================\n";
        cout << "  尝试密钥长度 m = " << m << "\n";
        cout << "========================================\n\n";

        // 阶段A: 频数分析 + 邻域搜索（快速路径）
        vector<int> base(m);
        iota(base.begin(), base.end(), 0);
        int permCount = 0;

        do {
            permCount++;
            string key(m, ' ');
            for (int i = 0; i < m; i++)
                key[base[i]] = (char)('A' + i);

            set<char> ks(key.begin(), key.end());
            if ((int)ks.size() != m) continue;

            string c2 = colDec(cfg.ciphertext, key);
            string freqKey = deriveVigKeyByFrequency(c2, m);
            CrackResult result;
            result.freqKey = freqKey;

            if (key == freqKey) {
                if (tryFullDecrypt(cfg, key, padPlain, validCombos, result)) {
                    printResult(cfg, result);
                    return;
                }
            }

            for (const string& nk : generateNeighborKeys(freqKey, m)) {
                if (nk == key) {
                    if (tryFullDecrypt(cfg, key, padPlain, validCombos, result)) {
                        result.freqKey = freqKey;
                        printResult(cfg, result);
                        return;
                    }
                }
            }
        } while (next_permutation(base.begin(), base.end()));

        cout << "    排列枚举(" << permCount
             << "种) + 频数分析 + 邻域搜索未命中\n";

        // 阶段B: 穷举所有长度 m 的无重复字母密钥（无 IC 筛选）
        cout << "    回退穷举所有长度 " << m << " 的无重复字母密钥...\n";
        vector<int> indices(m);
        int exhaustCount = 0;
        function<bool(int, int)> enumerate = [&](int pos, int mask) -> bool {
            if (pos == m) {
                string key(m, ' ');
                for (int i = 0; i < m; i++) key[i] = (char)('A' + indices[i]);
                exhaustCount++;
                CrackResult result;
                if (tryFullDecrypt(cfg, key, padPlain, validCombos, result)) {
                    result.freqKey = deriveVigKeyByFrequency(result.c2, m);
                    printResult(cfg, result);
                    return true;
                }
                return false;
            }
            for (int c = 0; c < 26; c++) {
                if (mask & (1 << c)) continue;
                indices[pos] = c;
                if (enumerate(pos + 1, mask | (1 << c))) return true;
            }
            return false;
        };
        if (enumerate(0, 0)) return;
        cout << "    穷举 " << exhaustCount << " 个密钥完成，密钥长度 " << m << " 无解\n\n";
    }

    cout << "\n[-] 破解失败\n";
    cout << "    可能原因:\n";
    cout << "    - 密钥长度超出搜索范围\n";
    cout << "    - 密文不符合 Hill→维吉尼亚→列置换 的加密模型\n";
    cout << "    - 已知明文片段不足以唯一确定 Hill 密钥矩阵\n";
}
