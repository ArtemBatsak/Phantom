#pragma once
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <array>
#include <vector>
#include <memory>
#include <mutex>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <string>
#include <fstream>
#include "logger/logger.h"

using asio::ip::tcp;

struct Packet {
    uint32_t type;
    uint32_t value;
};

struct link_par {
    std::shared_ptr<tcp::socket> data_socket;
    std::shared_ptr<tcp::socket> client_socket;
    uint64_t pair_id;
};

class Client : public std::enable_shared_from_this<Client> {
public:
	Client(const uint32_t id,
        const std::string& server_ip,
        const std::string& local_ip,
        uint16_t local_port,
        uint16_t data_port,
        asio::io_context& io);

    friend class ClientTest;
    friend class ObeliskIntegrationTest;

	void connectToServer(uint32_t otp); // Connect to the server and start the splicing process

    void remove_pair(uint64_t pair_id);
    void remove_all_pairs();
    uint16_t get_pool_size();

    // Test helpers (added to allow reliable unit testing of pair id and pool operations)
    uint64_t allocate_pair_id_for_test();
    void add_pair_for_test(const link_par& pair);
protected:
    void splice_loop(std::shared_ptr<tcp::socket> in_sock,
        std::shared_ptr<tcp::socket> out_sock,
        uint64_t pair_id);

    void start_splice(const link_par& pair);
private:
    
    uint64_t make_pair_id();
    

private:
    uint32_t id_;
    std::string server_ip_;
    std::string local_ip_;
    uint16_t local_port_;
    uint16_t data_port_;
    asio::io_context& io_;

    std::vector<link_par> link_pool_;
    std::mutex link_pool_mutex_;
    std::atomic<uint64_t> next_pair_id_;
};

void create_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    uint32_t data_port,
    uint32_t client_port,
    asio::io_context& io,
    const Config& config);

void async_receive_command(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<Client> client);

void connect_to_obelisk_server(asio::io_context& io, Config config);
