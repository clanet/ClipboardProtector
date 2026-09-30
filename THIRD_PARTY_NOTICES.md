# 第三方声明

项目自身代码采用 [MIT License](LICENSE)。以下组件保留各自的版权和许可。

| 组件 | 仓库位置 / 用途 | 来源与版本 | 许可 |
| --- | --- | --- | --- |
| Microsoft Detours | `third_party/Detours/`；构建 Hook DLL 时直接编译其部分源码 | [Microsoft/Detours](https://github.com/microsoft/Detours)，随附 README 标明 4.0.1 | [Microsoft MIT](licenses/Detours-MIT.txt) |
| BIP-39 英文词表 | `common/bip39_english.inc`；识别及校验英文助记词 | [bitcoin/bips](https://github.com/bitcoin/bips/blob/ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt)，2048 个词；2026-09-28 核对一致 | [BIP-39 MIT](licenses/BIP39-MIT.txt) |
| Catch2 | `third_party/Detours/tests/catch.hpp`；随 Detours 分发的测试依赖，不参与本项目 CMake 产品构建 | [Catch2 v2.13.0](https://github.com/catchorg/Catch2/tree/v2.13.0)，Copyright (c) 2020 Two Blue Cubes Ltd. | [Boost Software License 1.0](licenses/Catch2-BSL-1.0.txt) |

BIP-39 规范及作者信息见 [固定修订的规范](https://github.com/bitcoin/bips/blob/0d1b892ddb21c22def4af4541bfed7a2a3480e4a/bip-0039.mediawiki)。词表转换为 C++ 字符串数组，词的顺序和内容未变。

Detours 上游源码中的版权头、许可和其他声明继续保留。项目根目录的许可证不会替换第三方许可。

正式 ZIP 包将根目录 `LICENSE`、`licenses/Detours-MIT.txt` 和 `licenses/BIP39-MIT.txt` 的完整文本合并在 `README.en.md` 末尾，不再单独附带许可证文件。Catch2 不参与产品构建，不随二进制包分发；源码仓库仍保留全部许可文件。开发工具 Gitleaks 仅用于本地与 CI 检查，不随产品分发，其许可证位于 [上游仓库](https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE)。
