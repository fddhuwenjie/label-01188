/**
 * 古典密码三层加密破解程序 — 入口
 *
 * 加密流程: Hill密码(n=3) → 维吉尼亚密码 → 列置换密码
 *
 * 用法:
 *   ./cipher_cracker [密文] [已知明文] [已知密文头] [Hill第一行: r0 r1 r2] [最大密钥长度]
 *
 * 不带参数时使用默认题目数据。
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include "cracker.h"

using namespace std;

static void printUsage(const char* prog) {
    cerr << "用法: " << prog << " [选项]\n"
         << "  无参数        使用默认题目数据\n"
         << "  <密文> <已知明文> <已知密文头> <r0> <r1> <r2> [maxKeyLen]\n"
         << "                自定义输入\n";
}

int main(int argc, char* argv[]) {
    CrackConfig cfg;

    if (argc == 1) {
        // 默认题目数据
        cfg.ciphertext     = "EJBUJFNHQQRELMKPNIRQMSBPKVIZVLKSIYHCLGVFRITPEDFEFMQPEIWUKQHYKTIVUVSGQEJYDVH";
        cfg.knownPlain     = "CONFIDENTIALINFORMATION";
        cfg.knownCipherHead = "EJBUJFNHQQRELMKPNIRQMSB";
        cfg.hillRow1[0] = 11; cfg.hillRow1[1] = 2; cfg.hillRow1[2] = 19;
        cfg.maxKeyLen = 6;
        cfg.minKeyLen = 2;
    } else if (argc >= 7) {
        cfg.ciphertext      = argv[1];
        cfg.knownPlain      = argv[2];
        cfg.knownCipherHead = argv[3];
        cfg.hillRow1[0] = atoi(argv[4]);
        cfg.hillRow1[1] = atoi(argv[5]);
        cfg.hillRow1[2] = atoi(argv[6]);
        cfg.maxKeyLen = (argc >= 8) ? atoi(argv[7]) : 6;
        cfg.minKeyLen = 2;
    } else {
        printUsage(argv[0]);
        return 1;
    }

    // 输入校验
    if (cfg.ciphertext.empty()) {
        cerr << "错误: 密文不能为空\n"; return 1;
    }
    if (!isValidUpperAlpha(cfg.ciphertext)) {
        cerr << "错误: 密文必须全为大写字母 A-Z\n"; return 1;
    }
    if (cfg.knownPlain.empty()) {
        cerr << "错误: 已知明文不能为空\n"; return 1;
    }
    if (!isValidUpperAlpha(cfg.knownPlain)) {
        cerr << "错误: 已知明文必须全为大写字母 A-Z\n"; return 1;
    }
    if (!isValidUpperAlpha(cfg.knownCipherHead)) {
        cerr << "错误: 已知密文头必须全为大写字母 A-Z\n"; return 1;
    }
    if (cfg.knownCipherHead.length() > cfg.ciphertext.length()) {
        cerr << "错误: 已知密文头长度不能超过密文长度\n"; return 1;
    }
    if (cfg.knownPlain.length() < 3) {
        cerr << "错误: 已知明文至少需要3个字符（Hill密码块大小）\n"; return 1;
    }
    for (int i = 0; i < 3; i++) {
        if (cfg.hillRow1[i] < 0 || cfg.hillRow1[i] > 25) {
            cerr << "错误: Hill第一行元素必须在 0~25 范围内\n"; return 1;
        }
    }
    if (cfg.maxKeyLen < 2) {
        cerr << "错误: 最大密钥长度至少为2\n"; return 1;
    }

    crack(cfg);
    return 0;
}
