# 古典密码三层加密破解程序

## How to Run

### Docker 启动（推荐）

```bash
# 构建并运行
docker compose up --build -d

# 查看运行结果
docker logs cipher-cracker

# 停止并清理
docker compose down
```

或使用启动脚本（需已安装 Docker）：

```bash
bash start.sh
```

### 本地启动

```bash
cd backend
g++ -O3 -std=c++17 -o cipher_cracker main.cpp
./cipher_cracker
```

## Services

| 服务名 | 描述 | 端口 |
|--------|------|------|
| cipher-cracker | 古典密码破解程序 | 无（命令行程序） |

## 测试账号

本项目为纯命令行密码破解程序，无需账号登录。

## 题目内容

#### 题目背景

某敏感信息经过**三层古典密码加密**后生成密文，加密流程依次为：
**Hill密码（n=3）→ 维吉尼亚密码 → 列置换密码**。
已知少量明文片段和部分加密参数，要求编写程序逆向破解，还原完整原始明文。

#### 已知条件

1. **最终密文**（大写字母，无空格）：
   ```
   EJBUJFNHQQRELMKPNIRQMSBPKVIZVLKSIYHCLGVFRITPEDFEFMQPEIWUKQHYKTIVUVSGQEJYDVH
   ```

2. **已知明文片段**：原始明文开头为 `CONFIDENTIALINFORMATION`（前23个字符），对应密文前23个字符为 `EJBUJFNHQQRELMKPNIRQMSB`。

3. **加密流程细节**：
   - **第一层：Hill密码（n=3）** — 明文按3字符分组，不足补'X'；密钥矩阵A为3×3，gcd(det(A),26)=1，已知第一行 `[11, 2, 19]`
   - **第二层：维吉尼亚密码** — 密钥长度≤6，纯大写字母无重复
   - **第三层：列置换密码** — 密钥与维吉尼亚密钥相同（长度m），按密钥字典序重排列后按列读取

4. 所有加密基于26个英文字母（A=0, ..., Z=25）。

## 破解算法

程序严格按题面要求的四个步骤执行：

### 步骤1：逆列置换 — 推导列置换密钥和置换规则

利用"已知明文前23字符 ↔ 密文前23字符"的对应关系作为约束。对每个候选密钥长度 m（2~6中能整除密文长度的值），枚举所有 m! 种列排列，逆列置换得到 C2 候选，后续步骤验证其合理性。

### 步骤2：确定密钥长度 m — 卡西斯基/弗里德曼试验

在逆列置换后的 C2 上（而非最终密文上）执行：
- **卡西斯基试验**：查找 C2 中重复子串间距的公因数
- **弗里德曼试验**：计算 C2 按不同密钥长度分组后的平均重合指数(IC)，IC 接近 0.067（英文特征值）的长度即为 m

弗里德曼 IC 低于 0.04 的排列直接排除，有效缩小搜索空间。

### 步骤3：频数分析推导维吉尼亚密钥

在 C2 上按确定的密钥长度 m 分组，对每组做频数分析：
- 计算每个偏移量(0~25)下字母频率与标准英文频率的相关系数
- 选择相关系数最高的偏移量作为该位置的密钥字符

频数分析结果直接作为首选密钥验证。若因密文较短导致频数分析有偏差，对每个位置做 ±2 的邻域搜索覆盖误差。仅在邻域搜索也未命中时才回退到完整穷举（枚举所有长度为 m 的无重复字母密钥）。

### 步骤4：Hill密码解密 — 已知明文攻击

- 逆维吉尼亚得到 C1，利用已知明文片段与 C1 的对应关系
- 选取3组线性无关的明文块（行列式与26互素），通过 K = C × P⁻¹ (mod 26) 求解 Hill 密钥矩阵
- 验证第一行匹配 [11, 2, 19]，计算 A⁻¹ 解密得到完整明文
- 最终验证：重新加密后的密文前23字符必须等于已知的 `EJBUJFNHQQRELMKPNIRQMSB`

## 破解结果

- **维吉尼亚/列置换密钥**：`KEY`
- **Hill密钥矩阵**：`[[11,2,19],[3,7,4],[5,8,2]]`
- **完整明文**：`CONFIDENTIALINFORMATIONAPPLIEDCRYPTOGRAPHYCURRICULUMSTARTSMONDAYAFTERNOON`

## 项目结构

```
.
├── README.md              # 项目说明
├── docker-compose.yml     # Docker Compose 配置
├── start.sh              # 启动脚本（仅检查 Docker 可用性，不自动安装）
├── .gitignore
└── backend/
    ├── Dockerfile         # 多阶段构建（支持 ARM/x86）
    ├── main.cpp           # 主程序：破解流程、Hill密钥恢复
    ├── math_utils.h       # 模26数学工具（mod, gcd, 矩阵求逆）
    ├── hill.h             # Hill密码加密/解密
    ├── vigenere.h         # 维吉尼亚密码加密/解密
    ├── columnar.h         # 列置换密码加密/解密（不做额外填充）
    └── analysis.h         # 卡西斯基试验、弗里德曼试验、频数分析
```

## 依赖

- C++17、标准库（iostream, string, vector, algorithm, map, cmath, numeric）
- Docker（用于容器化构建运行）
