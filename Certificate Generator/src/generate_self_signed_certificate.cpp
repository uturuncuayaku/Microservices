#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>

namespace fs = std::filesystem;

std::string get_timestamp_folder_name() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm* gmt = std::localtime(&now_time);

    std::ostringstream oss;
    oss << "CertificateSelfSigned-"
        << std::put_time(gmt, "%Y%m%d-%H%M%S");
    return oss.str();
}

bool generate_self_signed_cert(const std::string& dir_path) {
    EVP_PKEY* pkey = nullptr;
    X509* x509 = nullptr;

    // 1. Generate private key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "❌ Failed to generate private key\n";
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // 2. Create X.509 certificate
    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);  // 1 year
    X509_set_version(x509, 2);  // v3
    X509_set_pubkey(x509, pkey);

    // 3. Set subject and issuer (self-signed)
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"AuthMicroservice", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // 4. Add basic constraints (X.509v3)
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "CA:FALSE");
    X509_add_ext(x509, ext, -1);
    X509_EXTENSION_free(ext);

    // 5. Sign certificate
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        std::cerr << "❌ Failed to sign certificate\n";
        return false;
    }

    // Ensure directory exists
    fs::create_directories(dir_path);

    std::string key_path = dir_path + "/private_key.pem";
    std::string cert_path = dir_path + "/server_cert.pem";

    // 6. Write private key
    FILE* key_fp = fopen(key_path.c_str(), "wb");
    if (!key_fp || !PEM_write_PrivateKey(key_fp, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "❌ Failed to write private key\n";
        return false;
    }
    fclose(key_fp);

    // 7. Write certificate
    FILE* cert_fp = fopen(cert_path.c_str(), "wb");
    if (!cert_fp || !PEM_write_X509(cert_fp, x509)) {
        std::cerr << "❌ Failed to write certificate\n";
        return false;
    }
    fclose(cert_fp);

    EVP_PKEY_free(pkey);
    X509_free(x509);
    return true;
}

int main() {
    std::string folder = get_timestamp_folder_name();

    if (generate_self_signed_cert(folder)) {
        std::cout << "✅ Certificate and key saved in: " << folder << "\n";
    } else {
        std::cerr << "❌ Generation failed.\n";
    }
    return 0;
}
// Note: Ensure you have OpenSSL installed and linked correctly to compile this code.
// Compile with: g++ generate_self_signed_certificate.cpp -o generate_self_signed_certificate -lssl -lcrypto
// This code generates a self-signed certificate and saves it along with the private key in a timestamped folder.
// The certificate is valid for 1 year and includes basic constraints. The private key is RSA   2048 bits.
// The certificate includes fields for country (C), organization (O), and common name (CN).
// The generated files are saved in PEM format, which is commonly used for certificates and keys.   