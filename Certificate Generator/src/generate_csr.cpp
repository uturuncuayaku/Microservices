#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;

std::string get_timestamp_folder_name() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm* gmt = std::localtime(&now_time);

    std::ostringstream oss;
    oss << "CertificateRequestSign-"
        << std::put_time(gmt, "%Y%m%d-%H%M%S");
    return oss.str();
}

bool generate_key_and_csr(const std::string& dir_path) {
    // 1. Generate RSA key
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // 2. Create a CSR
    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_version(req, 1);
    X509_NAME* name = X509_NAME_new();

    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char*)"auth.parzer0.local", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (unsigned char*)"Auth Server Project", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        (unsigned char*)"US", -1, -1, 0);

    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pkey);
    X509_REQ_sign(req, pkey, EVP_sha256());

    fs::create_directories(dir_path);
    std::string key_path = dir_path + "/private_key.pem";
    std::string csr_path = dir_path + "/csr.pem";

    // 3. Write private key
    FILE* key_file = fopen(key_path.c_str(), "wb");
    if (!key_file) return false;
    PEM_write_PrivateKey(key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(key_file);

    // 4. Write CSR
    FILE* csr_file = fopen(csr_path.c_str(), "wb");
    if (!csr_file) return false;
    PEM_write_X509_REQ(csr_file, req);
    fclose(csr_file);

    // Cleanup
    X509_NAME_free(name);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return true;
}

int main() {
    std::string folder = get_timestamp_folder_name();
    if (generate_key_and_csr(folder)) {
        std::cout << "✅ Key and CSR written to: " << folder << "\n";
    } else {
        std::cerr << "❌ Failed to generate key or CSR.\n";
    }
    return 0;
}
// Compile with: g++ -o generate_csr generate_csr.cpp -lssl -lcrypto
// Ensure OpenSSL is installed and linked correctly.
