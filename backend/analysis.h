#pragma once
/**
 * analysis.h — 密码分析工具
 *   卡西斯基试验、弗里德曼试验、频数分析
 */

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cmath>
#include "math_utils.h"

using std::string; using std::vector; using std::map; using std::pair;

static const double ENGLISH_FREQ[26] = {
    0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002,
    0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091,
    0.028, 0.010, 0.023, 0.001, 0.020, 0.001
};

/**
 * 卡西斯基试验：查找重复子串间距的公因数
 */
inline vector<int> kasiskiExamination(const string& cipher) {
    map<int, int> factorCount;
    for (int len = 3; len <= 5; len++) {
        map<string, vector<int>> positions;
        for (size_t i = 0; i + len <= cipher.length(); i++)
            positions[cipher.substr(i, len)].push_back(i);
        for (auto& p : positions) {
            if (p.second.size() >= 2) {
                for (size_t i = 1; i < p.second.size(); i++) {
                    int dist = p.second[i] - p.second[i-1];
                    for (int f = 2; f <= 6 && f <= dist; f++)
                        if (dist % f == 0) factorCount[f]++;
                }
            }
        }
    }
    vector<pair<int, int>> sorted(factorCount.begin(), factorCount.end());
    sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) {
        return a.second > b.second;
    });
    vector<int> result;
    for (auto& p : sorted)
        if (p.first >= 2 && p.first <= 6) result.push_back(p.first);
    return result;
}

/** 计算重合指数 IC */
inline double calcIC(const string& text) {
    int freq[26] = {0};
    for (char c : text)
        if (c >= 'A' && c <= 'Z') freq[c - 'A']++;
    int n = text.length();
    if (n <= 1) return 0;
    double sum = 0;
    for (int i = 0; i < 26; i++)
        sum += freq[i] * (freq[i] - 1);
    return sum / (n * (n - 1));
}

/**
 * 弗里德曼试验：对每个候选密钥长度计算平均 IC
 */
inline vector<pair<int, double>> friedmanTest(const string& cipher, int maxKeyLen = 6) {
    vector<pair<int, double>> results;
    for (int keyLen = 2; keyLen <= maxKeyLen; keyLen++) {
        vector<string> groups(keyLen);
        for (size_t i = 0; i < cipher.length(); i++)
            groups[i % keyLen] += cipher[i];
        double avgIC = 0;
        for (int i = 0; i < keyLen; i++)
            avgIC += calcIC(groups[i]);
        avgIC /= keyLen;
        results.push_back({keyLen, avgIC});
    }
    sort(results.begin(), results.end(), [](auto& a, auto& b) {
        return std::abs(a.second - 0.067) < std::abs(b.second - 0.067);
    });
    return results;
}

/** 频数分析推导单个位置的密钥字符 */
inline char analyzeFrequency(const string& group) {
    int freq[26] = {0};
    for (char c : group)
        if (c >= 'A' && c <= 'Z') freq[c - 'A']++;
    int n = group.length();
    if (n == 0) return 'A';
    double bestScore = -1e9;
    int bestShift = 0;
    for (int shift = 0; shift < 26; shift++) {
        double score = 0;
        for (int i = 0; i < 26; i++) {
            int decIdx = mod(i - shift, 26);
            double observed = (double)freq[i] / n;
            score += observed * ENGLISH_FREQ[decIdx];
        }
        if (score > bestScore) { bestScore = score; bestShift = shift; }
    }
    return (char)('A' + bestShift);
}

/** 频数分析推导完整维吉尼亚密钥 */
inline string deriveVigKeyByFrequency(const string& cipher, int keyLen) {
    vector<string> groups(keyLen);
    for (size_t i = 0; i < cipher.length(); i++)
        groups[i % keyLen] += cipher[i];
    string key;
    for (int i = 0; i < keyLen; i++)
        key += analyzeFrequency(groups[i]);
    return key;
}

/**
 * 综合卡西斯基 + 弗里德曼，返回候选密钥长度列表（2~6）
 */
inline vector<int> determineCandidateKeyLengths(const string& cipher) {
    auto friedman = friedmanTest(cipher, 6);
    auto kasiski  = kasiskiExamination(cipher);

    vector<int> candidates;
    for (int i = 0; i < (int)friedman.size() && i < 3; i++)
        candidates.push_back(friedman[i].first);
    for (int i = 0; i < (int)kasiski.size() && i < 3; i++)
        candidates.push_back(kasiski[i]);

    sort(candidates.begin(), candidates.end());
    candidates.erase(unique(candidates.begin(), candidates.end()), candidates.end());
    return candidates;
}
