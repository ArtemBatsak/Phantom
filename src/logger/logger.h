#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <filesystem>

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <iostream>

using json = nlohmann::json;

struct Config {
    std::string SERVER_IP = "";
    std::string LOCAL_IP = "";
    uint16_t CONTROL_PORT = 0;
    uint16_t LOCAL_PORT = 0;
    uint32_t ID_CLIENT = 0;
    uint32_t POOL_SIZE = 0;
};

Config start_up();

void init_logging();

