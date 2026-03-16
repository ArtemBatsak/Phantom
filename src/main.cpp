#include <asio.hpp>
#include <asio/ssl.hpp>
#include <iostream>
#include <memory>
#include <vector>
#include <thread>
#include <cstdint>
#include <chrono>
#include "server/server_class.h"
#include <logger/logger.h>
#include <nlohmann/json.hpp>
#include <fstream>


using asio::ip::tcp;
using namespace std;


using json = nlohmann::json;

struct Config {
    std::string SERVER_IP = "";
    std::string LOCAL_IP = "";
    uint16_t CONTROL_PORT = 0;
    uint16_t LOCAL_PORT = 0;
    uint32_t ID_CLIENT = 0;
    uint32_t POOL_SIZE = 0;
};

struct Packet {
    uint32_t type;
    uint32_t value;
};

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

Config start_up();

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

           
            asio::ssl::context ctx(asio::ssl::context::tlsv12_client);
            ctx.set_verify_mode(asio::ssl::verify_none);
            ctx.set_options(
                asio::ssl::context::default_workarounds |
                asio::ssl::context::no_sslv2 |
                asio::ssl::context::no_sslv3
            );

            auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io, ctx);

            tcp::resolver resolver(io);
            auto endpoints = resolver.resolve(config.SERVER_IP, std::to_string(config.CONTROL_PORT));

			// Connect to the server and perform SSL handshake
            asio::async_connect(ssl_sock->lowest_layer(), endpoints,
                [ssl_sock, &io, config](const asio::error_code& ec, const tcp::endpoint&) {
                    if (ec) {
                        spdlog::error("Connect failed: {}", ec.message());
                        return;
                    }

					// handshake with the server
                    ssl_sock->async_handshake(asio::ssl::stream_base::client,
                        [ssl_sock, &io, config](const asio::error_code& ec) {
                            if (ec) {
                                spdlog::error("SSL handshake failed: {}", ec.message());
                                return;
                            }

                            spdlog::info("Connected and SSL handshake successful with server at {}:{}", config.SERVER_IP, config.CONTROL_PORT);

                            
                            auto req_buf = std::make_shared<std::array<uint32_t, 2>>();
                            (*req_buf)[0] = htonl(config.ID_CLIENT);
                            (*req_buf)[1] = htonl(config.POOL_SIZE);

							// Send authorization request to the server
                            asio::async_write(*ssl_sock, asio::buffer(*req_buf),
                                [ssl_sock, req_buf, &io, config](const asio::error_code& ec, std::size_t) {
                                    if (ec) {
                                        spdlog::error("Failed to send request: {}", ec.message());
                                        return;
                                    }

									// Wait for server response containing assigned ports
                                    auto resp_buf = std::make_shared<std::array<uint32_t, 3>>();
                                    asio::async_read(*ssl_sock, asio::buffer(*resp_buf),
                                        [ssl_sock, resp_buf, &io, config](const asio::error_code& ec, std::size_t bytes_read) {
                                            if (ec || bytes_read != sizeof(*resp_buf)) {
                                                spdlog::error("Failed to read response: {}", ec.message());
                                                return;
                                            }

                                            uint32_t server_id = ntohl((*resp_buf)[0]);
                                            uint32_t client_port = ntohl((*resp_buf)[1]);
                                            uint32_t data_port = ntohl((*resp_buf)[2]);

                                            if (server_id != config.ID_CLIENT) {
                                                spdlog::error("Authorization failed: server returned ID {}, expected {}", server_id, config.ID_CLIENT);
                                                return;
                                            }

                                            spdlog::info("Authorized with server. Assigned client port: {}, data port: {}", client_port, data_port);
											// Create client instance to handle communication with the server
                                            create_client(ssl_sock, data_port, client_port, io, config);
                                        });
                                });
                        });
                });

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

void create_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    uint32_t data_port,
    uint32_t client_port,
    asio::io_context& io,
    const Config& config)
{
    auto client = std::make_shared<Client>(config.SERVER_IP, config.LOCAL_IP, config.LOCAL_PORT, static_cast<uint16_t>(data_port), io);
    async_receive_command(ssl_sock, client);
}


void async_receive_command(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<Client> client)
{
    auto packet = std::make_shared<Packet>();
	
    asio::async_read(*ssl_sock, asio::buffer(packet.get(), sizeof(Packet)),
        [ssl_sock, packet, client](asio::error_code ec, std::size_t length) {
			spdlog::info("Received command of length {} bytes", length);
			spdlog::info("Raw command data: type={}, value={}", ntohl(packet->type), ntohl(packet->value));
            if (!ec && length == sizeof(Packet)) {

                uint32_t type = ntohl(packet->type);
                uint32_t value = ntohl(packet->value);

                switch (type)
                {
                case 2:
                {
                    //spdlog::info("Received CONNECT command with value {}", value);
                    client->connectToServer(value);
                    break;
                }

                case 1:
                {
                    //spdlog::info("Received PING {}", value);

                    auto pong_pkt = std::make_shared<Packet>();
                    pong_pkt->type = htonl(3);
                    pong_pkt->value = htonl(value);

                    asio::async_write(
                        *ssl_sock,
                        asio::buffer(pong_pkt.get(), sizeof(Packet)),
                        [ssl_sock, pong_pkt](const asio::error_code& write_ec, std::size_t)
                        {
                            if (write_ec)
                            {
                                spdlog::error("Failed to send PONG response: {}", write_ec.message());
                            }
                        });



                    break;
                }

                default:
                {
                    spdlog::warn("Unknown command type {} value {}", type, value);
                    break;
                }
                }

                async_receive_command(ssl_sock, client);
            }
            else
            {
                spdlog::error("Control socket read error: {}", ec.message());
            }
        });
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

