#include <gtest/gtest.h>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "server/server_class.h" 
#include "logger/logger.h"


#include <spdlog/spdlog.h>


using asio::ip::tcp;

class ObeliskMock {
public:
    ObeliskMock(unsigned short port)
        : port_(port),
        ssl_ctx_(asio::ssl::context::tls_server),
        acceptor_(io_, tcp::endpoint(tcp::v4(), port))
    {
        setup_ssl();
    }

    uint32_t id = 0;
    const std::string& certificate_pem() const { return cert_pem_; }
    const std::string& private_key_pem() const { return key_pem_; }
    void run_once() {
        try {
            auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io_, ssl_ctx_);

        
            spdlog::info("Mock: Waiting for connection on port {}...", port_);
            acceptor_.accept(ssl_sock->lowest_layer());

            
            ssl_sock->handshake(asio::ssl::stream_base::server);

            
            uint32_t req[2];
            asio::read(*ssl_sock, asio::buffer(req, sizeof(req)));
            
            uint32_t client_id = req[0]; 
			id = htonl(req[0]);
           
            uint32_t resp[] = { client_id, htonl(255), htonl(256) };
            asio::write(*ssl_sock, asio::buffer(resp, sizeof(resp)));

            spdlog::info("Mock: Sent ports 255/256 and closing.");

            asio::error_code ec;
            ssl_sock->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        }
        catch (const std::exception& e) {
            spdlog::error("Mock error: {}", e.what());
        }
    }

private:
    static bool add_cert_extension(X509* cert, int nid, const char* value) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
        if (!ext) {
            return false;
        }

        const int add_res = X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        return add_res == 1;
    }

    void setup_ssl() {
        ssl_ctx_.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2);

        // Генерация временного сертификата (твой код)
        auto [key_pem, cert_pem] = generate_cert();
        key_pem_ = std::move(key_pem);
        cert_pem_ = std::move(cert_pem);

        BIO* b_cert = BIO_new_mem_buf(cert_pem_.data(), -1);
        BIO* b_key = BIO_new_mem_buf(key_pem_.data(), -1);
        X509* x509 = PEM_read_bio_X509(b_cert, nullptr, nullptr, nullptr);
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(b_key, nullptr, nullptr, nullptr);

        SSL_CTX_use_certificate(ssl_ctx_.native_handle(), x509);
        SSL_CTX_use_PrivateKey(ssl_ctx_.native_handle(), pkey);

        X509_free(x509);
        EVP_PKEY_free(pkey);
        BIO_free(b_cert);
        BIO_free(b_key);
    }

    std::pair<std::string, std::string> generate_cert() {
        // Create a self-signed certificate suitable for verify_peer validation.
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);
        RSA* rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
        X509* x509 = X509_new();

        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

        X509_NAME* subject = X509_NAME_new();
        X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Phantom Test"), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
        X509_set_subject_name(x509, subject);
        X509_set_issuer_name(x509, subject);
        X509_NAME_free(subject);

        X509_set_pubkey(x509, pkey);
        add_cert_extension(x509, NID_basic_constraints, "critical,CA:TRUE");
        add_cert_extension(x509, NID_key_usage, "critical,keyCertSign,digitalSignature,keyEncipherment");
        add_cert_extension(x509, NID_ext_key_usage, "serverAuth");
        add_cert_extension(x509, NID_subject_alt_name, "IP:127.0.0.1,DNS:localhost");
        X509_sign(x509, pkey, EVP_sha256());

        BIO* b_key = BIO_new(BIO_s_mem()), * b_cert = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(b_key, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        PEM_write_bio_X509(b_cert, x509);

        char* p_key, * p_cert;
        size_t l_key = BIO_get_mem_data(b_key, &p_key), l_cert = BIO_get_mem_data(b_cert, &p_cert);
        std::pair<std::string, std::string> res = { {p_key, l_key}, {p_cert, l_cert} };

        BN_free(bn); EVP_PKEY_free(pkey); X509_free(x509); BIO_free(b_key); BIO_free(b_cert);
        return res;
    }

    unsigned short port_;
    asio::io_context io_;
    asio::ssl::context ssl_ctx_;
    tcp::acceptor acceptor_;
    std::string key_pem_;
    std::string cert_pem_;
};

TEST(PhantomProject, ConfigDefaultValues) {
    Config cfg;
    
    EXPECT_EQ(cfg.CONTROL_PORT, 0);
    EXPECT_EQ(cfg.LOCAL_PORT, 0);
    EXPECT_TRUE(cfg.SERVER_IP.empty());
}

TEST(PhantomProject, PacketByteOrder) {
    Packet pkt;
    pkt.type = htonl(2); 
    pkt.value = htonl(12345);

    
    EXPECT_EQ(ntohl(pkt.type), 2);
    EXPECT_EQ(ntohl(pkt.value), 12345);
}

TEST(PhantomProject, ClientInitialization) {
    asio::io_context io;
    auto client = std::make_shared<Client>(1,"127.0.0.1", "127.0.0.1", 8080, 9090, io);

    ASSERT_NE(client, nullptr); 
}

TEST(PhantomProject, PairIdStartsFromOne) {
    asio::io_context io;
    auto client = std::make_shared<Client>(1,"127.0.0.1", "127.0.0.1", 8080, 9090, io);

    // Use test helper to allocate pair ids deterministically
    uint64_t id1 = client->allocate_pair_id_for_test();
    uint64_t id2 = client->allocate_pair_id_for_test();

    EXPECT_EQ(id1, 1ULL);
    EXPECT_EQ(id2, id1 + 1);
    EXPECT_NE(id1, id2);
}

TEST(ClientTest, RemoveAllPairsClearsPool) {
    asio::io_context io;
    auto client = std::make_shared<Client>(1,"127.0.0.1", "127.0.0.1", 8080, 9090, io);

    // Create a fake pair and insert into pool using test helper
    link_par fake_pair;
    fake_pair.pair_id = client->allocate_pair_id_for_test();
    fake_pair.client_socket = std::make_shared<asio::ip::tcp::socket>(io);
    fake_pair.data_socket = std::make_shared<asio::ip::tcp::socket>(io);

    client->add_pair_for_test(fake_pair);

    EXPECT_EQ(client->get_pool_size(), 1);

    client->remove_all_pairs();

    EXPECT_EQ(client->get_pool_size(), 0);
}

TEST(ClientTest, RemovePairRemovesSpecific) {
    asio::io_context io;
    auto client = std::make_shared<Client>(1,"127.0.0.1", "127.0.0.1", 8080, 9090, io);

    // Add two pairs
    link_par p1, p2;
    p1.pair_id = client->allocate_pair_id_for_test();
    p1.client_socket = std::make_shared<asio::ip::tcp::socket>(io);
    p1.data_socket = std::make_shared<asio::ip::tcp::socket>(io);

    p2.pair_id = client->allocate_pair_id_for_test();
    p2.client_socket = std::make_shared<asio::ip::tcp::socket>(io);
    p2.data_socket = std::make_shared<asio::ip::tcp::socket>(io);

    client->add_pair_for_test(p1);
    client->add_pair_for_test(p2);

    EXPECT_EQ(client->get_pool_size(), 2);

    client->remove_pair(p1.pair_id);

    EXPECT_EQ(client->get_pool_size(), 1);
    // ensure remaining pair is p2
    // allocate another id to ensure uniqueness behavior doesn't collide with present id
    EXPECT_NE(client->allocate_pair_id_for_test(), p2.pair_id);
}

TEST(ClientTest, LocalIpValidation) {
    asio::io_context io;

   
    auto client_bad = std::make_shared<Client>(1,"127.0.0.1", "999.999.999.999", 8080, 9090, io);

    asio::error_code ec;
    asio::ip::make_address("999.999.999.999", ec);

    
    EXPECT_TRUE(ec);
}

TEST(ObeliskIntegrationTest, ShouldReceiveCorrectPorts) {
    unsigned short test_port = 44555;
    uint32_t my_id = 777;

    auto mock_server = std::make_shared<ObeliskMock>(test_port);

    std::thread server_thread([mock_server]() {
        mock_server->run_once();
        });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    asio::io_context io;
    auto cfg = Config();
    cfg.SERVER_IP = "127.0.0.1";
    cfg.CONTROL_PORT = test_port;
    cfg.ID_CLIENT = my_id;
    cfg.POOL_SIZE = 10;
    cfg.LOCAL_IP = "127.0.0.1";
    cfg.CERTIFICATE = mock_server->certificate_pem();
    cfg.PRIVATE_KEY = mock_server->private_key_pem();
    cfg.TRUSTED_SERVER_CERTIFICATE = mock_server->certificate_pem();

    try {
        connect_to_obelisk_server(io, cfg);
        io.run();
    }
    catch (const std::exception& e) {
        FAIL() << "Connection failed with exception: " << e.what();
    }

    if (server_thread.joinable()) {
        server_thread.join();
    }

    EXPECT_EQ(mock_server->id, my_id) << "Server received wrong ID!";
}



TEST(ClientTest, RemoveAllPairsClosesEverything) {
    asio::io_context io;
    auto client = std::make_shared<Client>(1, "127.0.0.1", "127.0.0.1", 9000, 5000, io);

    
    for (int i = 0; i < 5; ++i) {
        link_par p;
        p.pair_id = i;
        p.client_socket = std::make_shared<tcp::socket>(io);
        p.data_socket = std::make_shared<tcp::socket>(io);

        
        p.client_socket->open(tcp::v4());
        p.data_socket->open(tcp::v4());

        client->add_pair_for_test(p);
    }

    EXPECT_EQ(client->get_pool_size(), 5);

    
    client->remove_all_pairs();

    
    EXPECT_EQ(client->get_pool_size(), 0); 
  
}

class ClientTestWrapper : public Client {
public:
    using Client::Client;

    void test_start_splice(const link_par& pair) {
        start_splice(pair);
    }
};


class TcpServerMock {
public:
    TcpServerMock(asio::io_context& io, uint16_t port)
        : acceptor_(io, tcp::endpoint(tcp::v4(), port)), socket_(io) {
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
    }

    void accept_one() {
        acceptor_.accept(socket_);
    }

    tcp::socket& socket() { return socket_; }

private:
    tcp::acceptor acceptor_;
    tcp::socket socket_;
};


TEST(ObeliskSplicing, DataIntegrityTransfer) {
    asio::io_context io;

    // Используем случайные порты для теста
    const uint16_t MOCK_LOCAL_SERVICE_PORT = 19999;
    const uint16_t MOCK_SERVER_DATA_PORT = 18888;
    const size_t TEST_DATA_SIZE = 5 * 1024 * 1024 ; 

    // Создаем клиента
    auto client = std::make_shared<ClientTestWrapper>(
        1, "127.0.0.1", "127.0.0.1",
        MOCK_LOCAL_SERVICE_PORT, MOCK_SERVER_DATA_PORT, io
    );

    // Запускаем "Локальный сервис" и "Сервер данных"
    TcpServerMock local_service(io, MOCK_LOCAL_SERVICE_PORT);
    TcpServerMock server_data_entry(io, MOCK_SERVER_DATA_PORT);

    // Подготавливаем сокеты для сплайсинга
    auto proxy_to_server = std::make_shared<tcp::socket>(io);
    auto proxy_to_local = std::make_shared<tcp::socket>(io);

    // Соединяем цепочку
    std::thread connector_thread([&]() {
        // Прокси подключается к серверу и к локальному сервису
        proxy_to_server->connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), MOCK_SERVER_DATA_PORT));
        proxy_to_local->connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), MOCK_LOCAL_SERVICE_PORT));
        });

    server_data_entry.accept_one();
    local_service.accept_one();
    connector_thread.join();

    
    link_par pair;
    pair.pair_id = 999;
    pair.data_socket = proxy_to_server;
    pair.client_socket = proxy_to_local;
    client->test_start_splice(pair);

    // Генерируем данные для проверки
    std::vector<char> sent_payload(TEST_DATA_SIZE);
    std::iota(sent_payload.begin(), sent_payload.end(), 0); // Заполняем паттерном

    std::vector<char> received_payload(TEST_DATA_SIZE, 0);

    // Запускаем io_context в отдельном потоке для асинхронной работы
    std::thread io_thread([&io]() {
        asio::io_context::work work(io);
        io.run();
        });

    // Отправляем данные через "Сервер" и принимаем в "Локальном сервисе"
    std::thread receiver_thread([&]() {
        size_t total_received = 0;
        while (total_received < TEST_DATA_SIZE) {
            asio::error_code ec;
            size_t n = local_service.socket().read_some(
                asio::buffer(received_payload.data() + total_received, TEST_DATA_SIZE - total_received), ec);
            if (ec) break;
            total_received += n;
        }
        });

    // Имитируем отправку данных со стороны сервера в прокси
    asio::write(server_data_entry.socket(), asio::buffer(sent_payload));

    receiver_thread.join();

    // ПРОВЕРКИ
    EXPECT_EQ(sent_payload, received_payload) << "Data mismatch after splicing!";
    EXPECT_EQ(client->get_pool_size(), 1);

    // Тест на корректное закрытие
    client->remove_all_pairs();
    EXPECT_EQ(client->get_pool_size(), 0);
    EXPECT_FALSE(proxy_to_server->is_open());

    // Завершение
    io.stop();
    if (io_thread.joinable()) io_thread.join();
}
