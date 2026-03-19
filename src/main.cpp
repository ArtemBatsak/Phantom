#include <asio.hpp>
#include <iostream>
#include <memory>
#include <vector>
#include <thread>
#include <cstdint>
#include <chrono>
#include "server/server_class.h"
#include <logger/logger.h>
#include "connect/connect.h"

using asio::ip::tcp;
using namespace std;



struct Ports {
    uint32_t data_port;
    uint32_t client_port;
};

void async_receive_command(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<Client> client);

void create_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    uint32_t data_port,
    uint32_t client_port,
    asio::io_context& io,
    const Config& config);

Config config;

int main() {
	// Initialize logging and create/load configuration
    init_logging();
    spdlog::info("Client starting up...");
    const Config config = start_up();

    while (true)
    {
        try {
            asio::io_context io;
            spdlog::info("Configuration loaded: SERVER_IP={}, LOCAL_IP={}, CONTROL_PORT={}, LOCAL_PORT={}, ID_CLIENT={}, POOL_SIZE={}",
                config.SERVER_IP, config.LOCAL_IP, config.CONTROL_PORT, config.LOCAL_PORT, config.ID_CLIENT, config.POOL_SIZE);

			connect_to_obelisk_server(io,config);

            io.run();
        }
        catch (const std::exception& e) {
            spdlog::error("Exception: {}", e.what());
        }
		// Wait before retrying connection to the server
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    

    return 0;
}




