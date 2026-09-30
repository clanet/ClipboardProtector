#include "crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <string_view>
#include <vector>

namespace clip {
namespace {

#include "bip39_english.inc"

bool IsTrimSpace(wchar_t value) {
    return iswspace(value) != 0;
}

bool TrimText(const std::wstring& input, size_t maxChars,
              std::wstring& output) {
    size_t first = 0;
    while (first < input.size() && IsTrimSpace(input[first])) ++first;
    size_t last = input.size();
    while (last > first && IsTrimSpace(input[last - 1])) --last;
    if (first == last || last - first > maxChars) return false;
    output.assign(input, first, last - first);
    return true;
}

int Base58Digit(wchar_t value) {
    static constexpr std::wstring_view alphabet =
        L"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const size_t index = alphabet.find(value);
    return index != std::wstring_view::npos ? static_cast<int>(index) : -1;
}

bool DecodeBase58(const std::wstring& text, std::vector<unsigned char>& out) {
    size_t zeroes = 0;
    while (zeroes < text.size() && text[zeroes] == L'1') ++zeroes;
    std::vector<unsigned char> base256(
        (text.size() - zeroes) * 733 / 1000 + 1);
    size_t length = 0;
    for (size_t index = zeroes; index < text.size(); ++index) {
        int carry = Base58Digit(text[index]);
        if (carry < 0) return false;
        size_t processed = 0;
        for (auto it = base256.rbegin();
             (carry != 0 || processed < length) && it != base256.rend();
             ++it, ++processed) {
            carry += 58 * *it;
            *it = static_cast<unsigned char>(carry & 0xff);
            carry >>= 8;
        }
        if (carry != 0) return false;
        length = processed;
    }
    auto significant = base256.end() - static_cast<ptrdiff_t>(length);
    out.assign(zeroes, 0);
    out.insert(out.end(), significant, base256.end());
    return true;
}

bool Sha256(const unsigned char* data, size_t size,
            std::array<unsigned char, 32>& output) {
    if (size > MAXDWORD) return false;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD returned = 0;
    bool ok = false;
    std::vector<unsigned char> object;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    if (BCRYPT_SUCCESS(BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
            &returned, 0)) &&
        returned == sizeof(objectSize)) {
        object.resize(objectSize);
        if (BCRYPT_SUCCESS(BCryptCreateHash(
                algorithm, &hash, object.data(), objectSize, nullptr, 0, 0)) &&
            BCRYPT_SUCCESS(BCryptHashData(
                hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0)) &&
            BCRYPT_SUCCESS(BCryptFinishHash(
                hash, output.data(), static_cast<ULONG>(output.size()), 0)))
            ok = true;
    }
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

bool HasBase58Checksum(const std::vector<unsigned char>& decoded) {
    if (decoded.size() < 5) return false;
    const size_t payloadSize = decoded.size() - 4;
    std::array<unsigned char, 32> first{};
    std::array<unsigned char, 32> second{};
    if (!Sha256(decoded.data(), payloadSize, first) ||
        !Sha256(first.data(), first.size(), second))
        return false;
    return std::equal(decoded.begin() + static_cast<ptrdiff_t>(payloadSize),
                      decoded.end(), second.begin());
}

bool IsBitcoinBase58(const std::wstring& address) {
    if (address.size() < 26 || address.size() > 35 ||
        (address.front() != L'1' && address.front() != L'3'))
        return false;
    std::vector<unsigned char> decoded;
    if (!DecodeBase58(address, decoded) || decoded.size() != 25 ||
        (decoded[0] != 0x00 && decoded[0] != 0x05))
        return false;
    return HasBase58Checksum(decoded);
}

int Bech32Digit(wchar_t value) {
    static constexpr std::wstring_view charset =
        L"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const size_t index = charset.find(value);
    return index != std::wstring_view::npos ? static_cast<int>(index) : -1;
}

uint32_t Bech32Polymod(const std::wstring& hrp,
                       const std::vector<unsigned char>& data) {
    static constexpr uint32_t generators[5] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t value = 1;
    auto step = [&](unsigned char item) {
        const uint32_t top = value >> 25;
        value = ((value & 0x1ffffff) << 5) ^ item;
        for (int bit = 0; bit < 5; ++bit)
            if ((top >> bit) & 1) value ^= generators[bit];
    };
    for (wchar_t item : hrp) step(static_cast<unsigned char>(item >> 5));
    step(0);
    for (wchar_t item : hrp) step(static_cast<unsigned char>(item & 31));
    for (unsigned char item : data) step(item);
    return value;
}

bool IsBitcoinBech32(const std::wstring& input, std::wstring& canonical) {
    if (input.size() < 14 || input.size() > 90) return false;
    bool lower = false;
    bool upper = false;
    for (wchar_t value : input) {
        if (value < 33 || value > 126) return false;
        lower = lower || (value >= L'a' && value <= L'z');
        upper = upper || (value >= L'A' && value <= L'Z');
    }
    if (lower && upper) return false;
    canonical = input;
    std::transform(canonical.begin(), canonical.end(), canonical.begin(),
                   [](wchar_t value) {
                       return static_cast<wchar_t>(
                           value >= L'A' && value <= L'Z'
                               ? value - L'A' + L'a'
                               : value);
                   });
    const size_t separator = canonical.rfind(L'1');
    if (separator != 2 || canonical.substr(0, separator) != L"bc" ||
        separator + 7 > canonical.size())
        return false;
    std::vector<unsigned char> data;
    data.reserve(canonical.size() - separator - 1);
    for (size_t index = separator + 1; index < canonical.size(); ++index) {
        const int digit = Bech32Digit(canonical[index]);
        if (digit < 0) return false;
        data.push_back(static_cast<unsigned char>(digit));
    }
    const uint32_t checksum = Bech32Polymod(L"bc", data);
    if (checksum != 1 && checksum != 0x2bc830a3) return false;
    const unsigned char version = data.front();
    if (version > 16 || data.size() <= 7) return false;

    std::vector<unsigned char> program;
    unsigned int accumulator = 0;
    int bits = 0;
    for (size_t index = 1; index + 6 < data.size(); ++index) {
        accumulator = ((accumulator << 5) | data[index]) & 0xfff;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            program.push_back(
                static_cast<unsigned char>((accumulator >> bits) & 0xff));
        }
    }
    if (bits >= 5 || ((accumulator << (8 - bits)) & 0xff) != 0 ||
        program.size() < 2 || program.size() > 40)
        return false;
    if (version == 0)
        return checksum == 1 &&
               (program.size() == 20 || program.size() == 32);
    return checksum == 0x2bc830a3;
}

bool IsEthereum(const std::wstring& address, std::wstring& canonical) {
    if (address.size() != 42 || address[0] != L'0' ||
        (address[1] != L'x' && address[1] != L'X'))
        return false;
    canonical = L"0x";
    canonical.reserve(address.size());
    for (size_t index = 2; index < address.size(); ++index) {
        const wchar_t value = address[index];
        if (!((value >= L'0' && value <= L'9') ||
              (value >= L'a' && value <= L'f') ||
              (value >= L'A' && value <= L'F')))
            return false;
        canonical.push_back(value >= L'A' && value <= L'F'
                                ? value - L'A' + L'a'
                                : value);
    }
    return true;
}

bool IsSolana(const std::wstring& address) {
    if (address.size() < 32 || address.size() > 44) return false;
    std::vector<unsigned char> decoded;
    return DecodeBase58(address, decoded) && decoded.size() == 32;
}

bool IsHexPrivateKey(const std::wstring& text) {
    size_t first = 0;
    if (text.size() >= 2 && text[0] == L'0' &&
        (text[1] == L'x' || text[1] == L'X'))
        first = 2;
    const size_t digits = text.size() - first;
    if (digits != 64 && digits != 128) return false;
    bool nonzero = false;
    for (size_t index = first; index < text.size(); ++index) {
        const wchar_t value = text[index];
        if (!((value >= L'0' && value <= L'9') ||
              (value >= L'a' && value <= L'f') ||
              (value >= L'A' && value <= L'F')))
            return false;
        nonzero = nonzero || value != L'0';
    }
    return nonzero;
}

bool IsBase58PrivateKey(const std::wstring& text) {
    if (text.size() < 50 || text.size() > 112) return false;
    std::vector<unsigned char> decoded;
    if (!DecodeBase58(text, decoded)) return false;

    // Bitcoin WIF, including the compressed-key marker.
    if ((decoded.size() == 37 || decoded.size() == 38) &&
        decoded[0] == 0x80 &&
        (decoded.size() == 37 || decoded[33] == 0x01))
        return HasBase58Checksum(decoded);

    // BIP-32 mainnet/testnet extended private keys (xprv/tprv).
    if (decoded.size() == 82) {
        const bool privateVersion =
            (decoded[0] == 0x04 && decoded[1] == 0x88 &&
             decoded[2] == 0xad && decoded[3] == 0xe4) ||
            (decoded[0] == 0x04 && decoded[1] == 0x35 &&
             decoded[2] == 0x83 && decoded[3] == 0x94);
        if (privateVersion && decoded[45] == 0x00)
            return HasBase58Checksum(decoded);
    }

    // BIP-38 encrypted private keys.
    if (decoded.size() == 43 && decoded[0] == 0x01 &&
        (decoded[1] == 0x42 || decoded[1] == 0x43))
        return HasBase58Checksum(decoded);

    // Solana keypair exports are commonly a Base58-encoded 64-byte secret.
    if (decoded.size() == 64) {
        return std::any_of(decoded.begin(), decoded.end(),
                           [](unsigned char value) { return value != 0; });
    }
    return false;
}

bool IsSolanaJsonPrivateKey(const std::wstring& text) {
    if (text.size() < 3 || text.front() != L'[' || text.back() != L']')
        return false;
    size_t index = 1;
    size_t count = 0;
    bool nonzero = false;
    auto skipSpace = [&] {
        while (index < text.size() && IsTrimSpace(text[index])) ++index;
    };
    skipSpace();
    while (index < text.size() && text[index] != L']') {
        if (count >= 64 || text[index] < L'0' || text[index] > L'9')
            return false;
        unsigned int value = 0;
        size_t digits = 0;
        while (index < text.size() && text[index] >= L'0' &&
               text[index] <= L'9') {
            value = value * 10 + static_cast<unsigned int>(text[index] - L'0');
            if (++digits > 3 || value > 255) return false;
            ++index;
        }
        nonzero = nonzero || value != 0;
        ++count;
        skipSpace();
        if (index >= text.size()) return false;
        if (text[index] == L',') {
            ++index;
            skipSpace();
            if (index >= text.size() || text[index] == L']') return false;
        } else if (text[index] != L']') {
            return false;
        }
    }
    return index + 1 == text.size() && (count == 32 || count == 64) &&
           nonzero;
}

int CompareMnemonicWord(std::wstring_view word, const wchar_t* candidate) {
    size_t index = 0;
    while (index < word.size() && candidate[index] != L'\0') {
        wchar_t value = word[index];
        if (value >= L'A' && value <= L'Z') value += L'a' - L'A';
        if (value != candidate[index]) return value < candidate[index] ? -1 : 1;
        ++index;
    }
    if (index == word.size() && candidate[index] == L'\0') return 0;
    return index == word.size() ? -1 : 1;
}

bool FindMnemonicWord(std::wstring_view word, unsigned short& result) {
    if (word.empty() || word.size() > 8) return false;
    for (wchar_t value : word) {
        if (!((value >= L'a' && value <= L'z') ||
              (value >= L'A' && value <= L'Z')))
            return false;
    }
    size_t first = 0;
    size_t last = _countof(kBip39EnglishWords);
    while (first < last) {
        const size_t middle = first + (last - first) / 2;
        const int compared =
            CompareMnemonicWord(word, kBip39EnglishWords[middle]);
        if (compared == 0) {
            result = static_cast<unsigned short>(middle);
            return true;
        }
        if (compared < 0)
            last = middle;
        else
            first = middle + 1;
    }
    return false;
}

bool IsBip39Mnemonic(const std::wstring& text) {
    std::array<std::wstring_view, 24> words{};
    size_t count = 0;
    size_t index = 0;
    while (index < text.size()) {
        while (index < text.size() && IsTrimSpace(text[index])) ++index;
        if (index == text.size()) break;
        const size_t first = index;
        while (index < text.size() && !IsTrimSpace(text[index])) ++index;
        if (count >= words.size()) return false;
        words[count++] = std::wstring_view(text).substr(first, index - first);
    }
    if (count != 12 && count != 24) return false;

    std::array<unsigned char, 33> packed{};
    size_t bitPosition = 0;
    for (size_t word = 0; word < count; ++word) {
        unsigned short wordIndex = 0;
        if (!FindMnemonicWord(words[word], wordIndex)) return false;
        for (int bit = 10; bit >= 0; --bit, ++bitPosition) {
            if ((wordIndex >> bit) & 1)
                packed[bitPosition / 8] |= static_cast<unsigned char>(
                    1u << (7 - bitPosition % 8));
        }
    }

    const size_t entropyBytes = count == 12 ? 16 : 32;
    const size_t checksumBits = count / 3;
    std::array<unsigned char, 32> digest{};
    if (!Sha256(packed.data(), entropyBytes, digest)) return false;
    for (size_t bit = 0; bit < checksumBits; ++bit) {
        const bool actual =
            (packed[(entropyBytes * 8 + bit) / 8] >>
             (7 - (entropyBytes * 8 + bit) % 8)) &
            1;
        const bool expected = (digest[bit / 8] >> (7 - bit % 8)) & 1;
        if (actual != expected) return false;
    }
    return true;
}

} // namespace

bool ParseCryptoAddress(const std::wstring& text, CryptoAddressKind& kind,
                        std::wstring& canonical) {
    kind = kCryptoAddressNone;
    canonical.clear();
    std::wstring address;
    if (!TrimText(text, 90, address)) return false;
    if (IsEthereum(address, canonical)) {
        kind = kCryptoAddressEthereum;
        return true;
    }
    if (IsBitcoinBase58(address)) {
        kind = kCryptoAddressBitcoin;
        canonical = address;
        return true;
    }
    std::wstring bech32;
    if (IsBitcoinBech32(address, bech32)) {
        kind = kCryptoAddressBitcoin;
        canonical = std::move(bech32);
        return true;
    }
    if (IsSolana(address)) {
        kind = kCryptoAddressSolana;
        canonical = address;
        return true;
    }
    return false;
}

bool ExtractCryptoAddresses(const std::wstring& text,
                            std::vector<CryptoAddress>& addresses) {
    addresses.clear();
    if (text.size() > kMaxCryptoTextLength) return false;
    const auto isTokenChar = [](wchar_t ch) {
        return (ch >= L'0' && ch <= L'9') ||
               (ch >= L'A' && ch <= L'Z') ||
               (ch >= L'a' && ch <= L'z') || ch == L'_';
    };
    for (size_t pos = 0; pos < text.size();) {
        if (!isTokenChar(text[pos])) {
            ++pos;
            continue;
        }
        const size_t start = pos;
        while (pos < text.size() && isTokenChar(text[pos])) ++pos;
        const size_t length = pos - start;
        if (length < 26 || length > 90) continue;
        CryptoAddress address;
        if (!ParseCryptoAddress(text.substr(start, length),
                                address.kind, address.canonical)) continue;
        if (addresses.size() == kMaxProtectedCryptoAddresses) {
            addresses.clear();
            return false;
        }
        addresses.push_back(std::move(address));
    }
    return true;
}

bool HasCryptoAddressReplacement(const std::vector<CryptoAddress>& before,
                                 const std::vector<CryptoAddress>& after) {
    if (before.empty() || after.empty()) return false;
    std::vector<bool> matched(after.size(), false);
    size_t retained = 0;
    for (const auto& address : before) {
        for (size_t index = 0; index < after.size(); ++index) {
            if (!matched[index] && address == after[index]) {
                matched[index] = true;
                ++retained;
                break;
            }
        }
    }
    return retained < before.size() && retained < after.size();
}

bool IsPrivateKeyOrMnemonicContent(const std::wstring& text) {
    std::wstring value;
    if (!TrimText(text, 2048, value)) return false;
    return IsHexPrivateKey(value) || IsBase58PrivateKey(value) ||
           IsSolanaJsonPrivateKey(value) || IsBip39Mnemonic(value);
}

} // namespace clip
