 #include "logger.h"

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
        f >> j;

        config.SERVER_IP = j.value("SERVER_IP", config.SERVER_IP);
        config.LOCAL_IP = j.value("LOCAL_IP", config.LOCAL_IP);
        config.CONTROL_PORT = j.value("CONTROL_PORT", config.CONTROL_PORT);
        config.LOCAL_PORT = j.value("LOCAL_PORT", config.LOCAL_PORT);
        config.ID_CLIENT = j.value("ID_CLIENT", config.ID_CLIENT);
        config.POOL_SIZE = j.value("POOL_SIZE", config.POOL_SIZE);

        std::cout << "Config loaded\n";
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
        std::cout << "LOCAL_PORT: ";
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

    j = {
        {"SERVER_IP", config.SERVER_IP},
        {"LOCAL_IP", config.LOCAL_IP},
        {"CONTROL_PORT", config.CONTROL_PORT},
        {"LOCAL_PORT", config.LOCAL_PORT},
        {"ID_CLIENT", config.ID_CLIENT},
        {"POOL_SIZE", config.POOL_SIZE}
    };

    std::ofstream o("config.json");
    o << j.dump(4);

    return config;
}

