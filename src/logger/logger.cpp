 #include "logger.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace {
    uint16_t parse_u16_or_default(const json& j, const char* key, uint16_t default_value) {
        if (!j.contains(key) || j.at(key).is_null()) {
            return default_value;
        }

        if (j.at(key).is_number_unsigned() || j.at(key).is_number_integer()) {
            return j.at(key).get<uint16_t>();
        }

        if (j.at(key).is_string()) {
            const auto value = j.at(key).get<std::string>();
            if (value.empty()) {
                return default_value;
            }

            return static_cast<uint16_t>(std::stoul(value));
        }

        return default_value;
    }

    uint32_t parse_u32_or_default(const json& j, const char* key, uint32_t default_value) {
        if (!j.contains(key) || j.at(key).is_null()) {
            return default_value;
        }

        if (j.at(key).is_number_unsigned() || j.at(key).is_number_integer()) {
            return j.at(key).get<uint32_t>();
        }

        if (j.at(key).is_string()) {
            const auto value = j.at(key).get<std::string>();
            if (value.empty()) {
                return default_value;
            }

            return static_cast<uint32_t>(std::stoul(value));
        }

        return default_value;
    }

    bool is_key_matching_certificate(const std::string& certificate_pem, const std::string& private_key_pem) {
        if (certificate_pem.empty() || private_key_pem.empty()) {
            return false;
        }

        BIO* cert_bio = BIO_new_mem_buf(certificate_pem.data(), static_cast<int>(certificate_pem.size()));
        BIO* key_bio = BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size()));
        if (!cert_bio || !key_bio) {
            if (cert_bio) BIO_free(cert_bio);
            if (key_bio) BIO_free(key_bio);
            return false;
        }

        X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);

        bool matches = false;
        if (cert && key) {
            matches = X509_check_private_key(cert, key) == 1;
        }

        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
        BIO_free(cert_bio);
        BIO_free(key_bio);
        return matches;
    }
}

void init_logging()
{
   
    if (spdlog::get("phantom"))
        return;

    namespace fs = std::filesystem;

    const fs::path log_dir = "logs";
    fs::create_directories(log_dir);
    const fs::path log_file = log_dir / "phantom.log";

    constexpr std::size_t max_file_size = 5 * 1024 * 1024;
    constexpr std::size_t max_files = 5;

    
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file.string(), max_file_size, max_files
    );
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    file_sink->set_level(spdlog::level::info);
    console_sink->set_level(spdlog::level::info);

    std::vector<spdlog::sink_ptr> sinks{ console_sink, file_sink };

    auto logger = std::make_shared<spdlog::logger>("phantom", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::info);
    logger->set_pattern("[%d.%m.%Y %H:%M:%S.%e] [%l] %v");
    logger->flush_on(spdlog::level::info);

    spdlog::set_default_logger(logger);

    spdlog::info("Logger initialized");
}

Config start_up() {

    Config config;
    json j;

    std::ifstream f("config.json");

    if (f.good()) {
        try {
            f >> j;

            config.SERVER_IP = j.value("SERVER_IP", config.SERVER_IP);
            config.LOCAL_IP = j.value("LOCAL_IP", config.LOCAL_IP);
            config.CONTROL_PORT = parse_u16_or_default(j, "CONTROL_PORT", config.CONTROL_PORT);
            config.LOCAL_PORT = parse_u16_or_default(j, "LOCAL_PORT", config.LOCAL_PORT);
            config.ID_CLIENT = parse_u32_or_default(j, "ID_CLIENT", config.ID_CLIENT);
            config.POOL_SIZE = parse_u32_or_default(j, "POOL_SIZE", config.POOL_SIZE);
            config.CERTIFICATE = j.value("CERTIFICATE", config.CERTIFICATE);
            config.PRIVATE_KEY = j.value("PRIVATE_KEY", config.PRIVATE_KEY);
            config.TRUSTED_SERVER_CERTIFICATE = j.value("TRUSTED_SERVER_CERTIFICATE", config.TRUSTED_SERVER_CERTIFICATE);

            std::cout << "Config loaded\n";
        }
        catch (const std::exception& e) {
            throw std::runtime_error(std::string("Config is broken: invalid format. ") + e.what());
        }
    }

    if (config.SERVER_IP.empty()) {
        std::cout << "SERVER_IP: ";
        std::cin >> config.SERVER_IP;
    }

    if (config.LOCAL_IP.empty()) {
        std::cout << "LOCAL_IP: ";
        std::cin >> config.LOCAL_IP;
    }

    if (config.CONTROL_PORT == 0) {
        std::cout << "CONTROL_PORT: ";
        std::cin >> config.CONTROL_PORT;
    }

    if (config.LOCAL_PORT == 0) {
        std::cout << "Введите локальный порт (LOCAL_PORT): ";
        std::cin >> config.LOCAL_PORT;
    }

    if (config.ID_CLIENT == 0) {
        std::cout << "ID_CLIENT: ";
        std::cin >> config.ID_CLIENT;
    }

    if (config.POOL_SIZE == 0) {
        std::cout << "POOL_SIZE: ";
        std::cin >> config.POOL_SIZE;
    }
    if (config.CERTIFICATE.empty()) {
        throw std::runtime_error("Config is broken: CERTIFICATE is missing.");
    }

    if (config.PRIVATE_KEY.empty()) {
        throw std::runtime_error("Config is broken: PRIVATE_KEY is missing.");
    }

    if (config.TRUSTED_SERVER_CERTIFICATE.empty()) {
        throw std::runtime_error("Config is broken: TRUSTED_SERVER_CERTIFICATE is missing.");
    }

    if (!is_key_matching_certificate(config.CERTIFICATE, config.PRIVATE_KEY)) {
        throw std::runtime_error("Config is broken: client PRIVATE_KEY does not match CERTIFICATE.");
    }

    j = {
        {"SERVER_IP", config.SERVER_IP},
        {"LOCAL_IP", config.LOCAL_IP},
        {"CONTROL_PORT", config.CONTROL_PORT},
        {"LOCAL_PORT", config.LOCAL_PORT},
        {"ID_CLIENT", config.ID_CLIENT},
        {"POOL_SIZE", config.POOL_SIZE},
        {"CERTIFICATE", config.CERTIFICATE},
        {"PRIVATE_KEY", config.PRIVATE_KEY},
        {"TRUSTED_SERVER_CERTIFICATE", config.TRUSTED_SERVER_CERTIFICATE}
    };

    std::ofstream o("config.json");
    o << j.dump(4);

    return config;
}
