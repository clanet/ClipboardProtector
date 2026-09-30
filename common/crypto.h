#pragma once

#include <string>
#include <vector>

namespace clip {

enum CryptoAddressKind : unsigned char {
    kCryptoAddressNone = 0,
    kCryptoAddressBitcoin = 1,
    kCryptoAddressEthereum = 2,
    kCryptoAddressSolana = 3,
};

// Recognizes mainnet BTC addresses, 20-byte EVM addresses, and 32-byte
// Solana public keys. The canonical value is safe to compare across copies.
bool ParseCryptoAddress(const std::wstring& text, CryptoAddressKind& kind,
                        std::wstring& canonical);

struct CryptoAddress {
    CryptoAddressKind kind = kCryptoAddressNone;
    std::wstring canonical;
    bool operator==(const CryptoAddress& other) const {
        return kind == other.kind && canonical == other.canonical;
    }
};

constexpr size_t kMaxProtectedCryptoAddresses = 256;
constexpr size_t kMaxCryptoTextLength = 65536;

// Extract whole ASCII-alphanumeric tokens, including addresses next to Chinese
// prose or punctuation. Never recognize a substring of a longer identifier.
// False means the bounded scan could not represent the complete address list.
bool ExtractCryptoAddresses(const std::wstring& text,
                            std::vector<CryptoAddress>& addresses);

// Compare multisets: replacement requires both a removed and an added address.
// Reordering, adding, deleting, and editing ordinary prose are not replacement.
bool HasCryptoAddressReplacement(const std::vector<CryptoAddress>& before,
                                 const std::vector<CryptoAddress>& after);

// Matches a complete supported private key or a validated 12/24-word English
// BIP-39 mnemonic. Addresses are deliberately handled by ParseCryptoAddress.
bool IsPrivateKeyOrMnemonicContent(const std::wstring& text);

} // namespace clip
