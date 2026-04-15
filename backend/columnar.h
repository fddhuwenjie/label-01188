#pragma once
/**
 * columnar.h — 列置换密码加密/解密
 *
 * 支持密文长度不是密钥长度整数倍的情况（最后一行不满）。
 */

#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>

using std::string; using std::vector; using std::pair;

/**
 * 列置换加密：按行填入 m 列矩阵，按密钥字典序重排列后按列读取。
 */
inline string colEnc(const string& p, const string& key) {
    if (key.empty()) throw std::invalid_argument("colEnc: key must not be empty");
    if (p.empty()) return "";

    int cols = key.length();
    int fullRows = p.length() / cols;
    int extra = p.length() % cols;
    int totalRows = fullRows + (extra > 0 ? 1 : 0);

    vector<vector<int>> mat(totalRows, vector<int>(cols, -1));
    for (size_t i = 0; i < p.length(); i++)
        mat[i / cols][i % cols] = p[i] - 'A';

    vector<pair<char, int>> order;
    for (int i = 0; i < cols; i++)
        order.push_back({key[i], i});
    sort(order.begin(), order.end());

    string r;
    for (auto& o : order)
        for (int row = 0; row < totalRows; row++)
            if (mat[row][o.second] != -1)
                r += (char)(mat[row][o.second] + 'A');
    return r;
}

/**
 * 列置换解密（逆操作）
 */
inline string colDec(const string& c, const string& key) {
    if (key.empty()) throw std::invalid_argument("colDec: key must not be empty");
    if (c.empty()) return "";

    int cols = key.length();
    int fullRows = c.length() / cols;
    int extra = c.length() % cols;
    int totalRows = fullRows + (extra > 0 ? 1 : 0);

    vector<pair<char, int>> order;
    for (int i = 0; i < cols; i++)
        order.push_back({key[i], i});
    sort(order.begin(), order.end());

    vector<int> colRows(cols);
    for (int i = 0; i < cols; i++) {
        int origCol = order[i].second;
        colRows[i] = (origCol < extra) ? totalRows : fullRows;
    }

    vector<vector<int>> mat(totalRows, vector<int>(cols, -1));
    int idx = 0;
    for (int i = 0; i < cols; i++) {
        int origCol = order[i].second;
        for (int row = 0; row < colRows[i]; row++)
            mat[row][origCol] = c[idx++] - 'A';
    }

    string r;
    for (int row = 0; row < totalRows; row++)
        for (int col = 0; col < cols; col++)
            if (mat[row][col] != -1)
                r += (char)(mat[row][col] + 'A');
    return r;
}
