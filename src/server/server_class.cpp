#include "server/server_class.h"

void connect_to_obelisk_server(asio::io_context& io, Config config) {
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
}

void create_client(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    uint32_t data_port,
    uint32_t client_port,
    asio::io_context& io,
    const Config& config)
{
    auto client = std::make_shared<Client>(config.ID_CLIENT,config.SERVER_IP, config.LOCAL_IP, config.LOCAL_PORT, static_cast<uint16_t>(data_port), io);
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

//=============================== Client Class Implementation ===============================
Client::Client(const uint32_t id,
    const std::string& server_ip,
    const std::string& local_ip,
    uint16_t local_port,
    uint16_t data_port,
    asio::io_context& io)
	: id_(id)
    , server_ip_(server_ip)
    , local_ip_(local_ip)
    , local_port_(local_port)
    , data_port_(data_port)
    , io_(io)
    , next_pair_id_(1)
{
}
// Connect to the server, send the OTP, and start the splicing process, use otp as a unique identifier for the connection
void Client::connectToServer(uint32_t otp)
{
    auto self = shared_from_this();
    auto data_sock = std::make_shared<tcp::socket>(io_);

    tcp::resolver resolver(io_);
    auto endpoints = resolver.resolve(server_ip_, std::to_string(data_port_));

    asio::async_connect(*data_sock, endpoints,
        [self, data_sock, otp](const asio::error_code& ec, const tcp::endpoint&)
        {
            if (ec) {
                spdlog::error("Failed to connect: {}", ec.message());
                return;
            }

            
            auto pkt = std::make_shared<Packet>(htonl(self->id_), htonl(otp));

            asio::async_write(*data_sock, asio::buffer(pkt.get(), sizeof(Packet)),
                [self, data_sock, pkt](const asio::error_code& ec_write, std::size_t)
                {
                    if (ec_write) {
                        spdlog::error("Failed to send Packet: {}", ec_write.message());
                        return;
                    }

                    
                    auto buffer = std::make_shared<std::array<char, 4096>>();
                    data_sock->async_read_some(asio::buffer(*buffer),
                        [self, data_sock, buffer](const asio::error_code& ec_read, std::size_t bytes_read)
                        {
                            if (ec_read || bytes_read == 0) return;

                            
                            auto client_sock = std::make_shared<tcp::socket>(self->io_);

                            asio::error_code ec_addr;
                            auto local_ep = tcp::endpoint(asio::ip::make_address(self->local_ip_, ec_addr), self->local_port_);

                            client_sock->async_connect(local_ep,
                                [self, data_sock, client_sock, buffer, bytes_read](const asio::error_code& ec_conn)
                                {
                                    if (ec_conn) return;

                                   
                                    asio::async_write(*client_sock, asio::buffer(buffer->data(), bytes_read),
                                        [self, data_sock, client_sock](const asio::error_code& ec_write2, std::size_t)
                                        {
                                            if (ec_write2) return;

                                            link_par pair;
                                            pair.data_socket = data_sock;
                                            pair.client_socket = client_sock;
                                            pair.pair_id = self->make_pair_id();

                                            self->start_splice(pair);
                                        });
                                });
                        });
                });
        });
}
// Splice loop to read from in_sock and write to out_sock, and vice versa, for the given pair_id
void Client::splice_loop(std::shared_ptr<tcp::socket> in_sock,
    std::shared_ptr<tcp::socket> out_sock,
    uint64_t pair_id)
{
        auto self = shared_from_this();

        auto buffer = std::make_shared<std::array<char, 64 * 1024>>();

        
        auto do_read = std::make_shared<std::function<void()>>();

        *do_read = [self, in_sock, out_sock, pair_id, buffer, do_read]() mutable
            {
                in_sock->async_read_some(
                    asio::buffer(*buffer),
                    [self, in_sock, out_sock, pair_id, buffer, do_read]
                    (const asio::error_code& ec, std::size_t bytes)
                    {
                        if (ec || bytes == 0) {
                            if (ec != asio::error::eof &&
                                ec != asio::error::operation_aborted) {
                                spdlog::error("Pair {}: read error ({}): {}",
                                    pair_id, ec.value(), ec.message());
                            }
                            self->remove_pair(pair_id);
                            return;
                        }

                       
                        asio::async_write(
                            *out_sock,
                            asio::buffer(buffer->data(), bytes),
                            [self, pair_id, do_read]
                            (const asio::error_code& ec_write, std::size_t)
                            {
                                if (ec_write) {
                                    if (ec_write != asio::error::eof &&
                                        ec_write != asio::error::operation_aborted) {
                                        spdlog::error("Pair {}: write error ({}): {}",
                                            pair_id, ec_write.value(), ec_write.message());
                                    }
                                    self->remove_pair(pair_id);
                                    return;
                                }

                                (*do_read)(); 
                            }
                        );
                    }
                );
            };

        (*do_read)();
    
}

void Client::start_splice(const link_par& pair)
{
    {
        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        link_pool_.push_back(pair);
    }

    splice_loop(pair.client_socket, pair.data_socket, pair.pair_id);
    splice_loop(pair.data_socket, pair.client_socket, pair.pair_id);
}

uint64_t Client::make_pair_id()
{
    for (;;) {
        uint64_t id = next_pair_id_.fetch_add(1, std::memory_order_relaxed);
        if (id == 0) continue;

        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        auto it = std::find_if(link_pool_.begin(), link_pool_.end(),
            [id](const link_par& p) { return p.pair_id == id; });

        if (it == link_pool_.end())
            return id;
    }
}

void Client::remove_pair(uint64_t pair_id)
{
    std::shared_ptr<tcp::socket> client_sock;
    std::shared_ptr<tcp::socket> data_sock;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        auto it = std::find_if(link_pool_.begin(), link_pool_.end(),
            [pair_id](const link_par& p) { return p.pair_id == pair_id; });

        if (it == link_pool_.end())
            return;

        client_sock = it->client_socket;
        data_sock = it->data_socket;
        link_pool_.erase(it);
    }

    if (client_sock && client_sock->is_open()) {
        asio::error_code ec;
        client_sock->shutdown(tcp::socket::shutdown_both, ec);
        client_sock->close(ec);
    }

    if (data_sock && data_sock->is_open()) {
        asio::error_code ec;
        data_sock->shutdown(tcp::socket::shutdown_both, ec);
        data_sock->close(ec);
    }
}

void Client::remove_all_pairs()
{
    std::vector<link_par> pairs;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex_);
        pairs.swap(link_pool_);
    }

    for (auto& p : pairs) {
        if (p.client_socket && p.client_socket->is_open()) {
            asio::error_code ec;
            p.client_socket->shutdown(tcp::socket::shutdown_both, ec);
            p.client_socket->close(ec);
        }

        if (p.data_socket && p.data_socket->is_open()) {
            asio::error_code ec;
            p.data_socket->shutdown(tcp::socket::shutdown_both, ec);
            p.data_socket->close(ec);
        }
    }
}

uint16_t Client::get_pool_size() {
    std::lock_guard<std::mutex> lock(link_pool_mutex_);
	return static_cast<uint16_t>(link_pool_.size());

}

// ---------------- Test helpers implementation ----------------
uint64_t Client::allocate_pair_id_for_test() {
    // returns a unique pair id (uses internal make_pair_id)
    return make_pair_id();
}

void Client::add_pair_for_test(const link_par& pair) {
    std::lock_guard<std::mutex> lock(link_pool_mutex_);
    link_pool_.push_back(pair);
}
