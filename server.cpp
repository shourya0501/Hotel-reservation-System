// =============================================================================
// server.cpp : Online Hotel Reservation System, REST backend (C++17)
//
// Endpoints
//   POST   /api/auth/register    create guest account              -> 201 + token
//   POST   /api/auth/login       sign in                           -> 200 + token
//   GET    /api/rooms/search     live availability and tariff      -> 200
//   POST   /api/bookings         PENDING reservation and bill      -> 201
//   DELETE /api/bookings/{id}    soft cancel (status = CANCELLED)  -> 200
//   POST   /api/payments         verify card, capture, confirm     -> 200
//   GET    /api/health           database status                   -> 200 / 503
//
// Build (Ubuntu 22.04 / 24.04):
//   sudo apt install build-essential libmysqlcppconn-dev libssl-dev nlohmann-json3-dev
//   g++ -std=c++17 -O2 -Wall -Wextra server.cpp -o hotel_server \
//       -lmysqlcppconn8 -lssl -lcrypto -pthread
//   If <jdbc/...> headers are not found, add -I/usr/include/mysql-cppconn-8
// =============================================================================
#include "httplib.h"
#include <nlohmann/json.hpp>

#include <jdbc/mysql_driver.h>
#include <jdbc/mysql_connection.h>
#include <jdbc/cppconn/exception.h>
#include <jdbc/cppconn/prepared_statement.h>
#include <jdbc/cppconn/resultset.h>
#include <jdbc/cppconn/statement.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;
using PS = std::unique_ptr<sql::PreparedStatement>;
using RS = std::unique_ptr<sql::ResultSet>;

// ------------------------------------------------------------ Business rules
constexpr long long BOOKING_FEE_PAISE = 25000;  // Rs 250.00 flat booking fee
constexpr long long TAX_BASIS_POINTS  = 1200;   // 12.00 % (assumed; set per tariff band)
constexpr int       PBKDF2_ITERATIONS = 120000;
constexpr long long TOKEN_TTL_SECONDS = 2 * 60 * 60;
constexpr int       HOLD_SECONDS      = 15 * 60;  // must match the 15-minute expiry event in the SQL file
constexpr const char* HOTEL_NAME      = "Sunrise Residency (Demo Property)";

struct HttpError { int status; std::string message; };
std::string g_secret;  // HMAC key for session tokens, loaded from AUTH_SECRET

void send_error(httplib::Response& res, int status, const std::string& message) {
    res.status = status;
    res.set_content(json{{"error", message}}.dump(), "application/json");
}

// ------------------------------------------------------------ Crypto helpers
std::string to_hex(const unsigned char* data, std::size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

std::string random_hex(std::size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1)
        throw std::runtime_error("CSPRNG failure");
    return to_hex(buf.data(), bytes);
}

std::string hmac_hex(const std::string& key, const std::string& message) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(), out, &len);
    return to_hex(out, len);
}

// Constant-time comparison: avoids leaking how many leading characters matched.
bool secure_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

std::string derive_key(const std::string& password, const std::string& salt, int iterations) {
    unsigned char out[32];
    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                      reinterpret_cast<const unsigned char*>(salt.data()),
                      static_cast<int>(salt.size()),
                      iterations, EVP_sha256(), sizeof out, out);
    return to_hex(out, sizeof out);
}

std::string hash_password(const std::string& password) {
    const std::string salt = random_hex(16);
    return "pbkdf2_sha256$" + std::to_string(PBKDF2_ITERATIONS) + "$" + salt + "$" +
           derive_key(password, salt, PBKDF2_ITERATIONS);
}

bool verify_password(const std::string& password, const std::string& stored) {
    std::vector<std::string> parts;
    std::stringstream ss(stored);
    for (std::string part; std::getline(ss, part, '$');) parts.push_back(part);
    if (parts.size() != 4 || parts[0] != "pbkdf2_sha256") return false;
    return secure_equal(derive_key(password, parts[2], std::stoi(parts[1])), parts[3]);
}

// Token format: "<customer_id>:<expiry_epoch>.<hmac_hex>"
std::string issue_token(long long customer_id) {
    const long long expires = static_cast<long long>(std::time(nullptr)) + TOKEN_TTL_SECONDS;
    const std::string payload = std::to_string(customer_id) + ":" + std::to_string(expires);
    return payload + "." + hmac_hex(g_secret, payload);
}

std::optional<long long> verify_token(const std::string& token) {
    const std::size_t dot = token.rfind('.');
    if (dot == std::string::npos) return std::nullopt;
    const std::string payload = token.substr(0, dot);
    if (!secure_equal(hmac_hex(g_secret, payload), token.substr(dot + 1))) return std::nullopt;
    const std::size_t colon = payload.find(':');
    const long long customer_id = std::stoll(payload.substr(0, colon));
    const long long expires = std::stoll(payload.substr(colon + 1));
    if (static_cast<long long>(std::time(nullptr)) > expires) return std::nullopt;
    return customer_id;
}

long long require_customer(const httplib::Request& req) {
    const std::string header = req.get_header_value("Authorization");
    if (header.rfind("Bearer ", 0) == 0) {
        if (auto id = verify_token(header.substr(7))) return *id;
    }
    throw HttpError{401, "Please sign in to continue"};
}

// ------------------------------------------------------------ Dates and money
struct Stay { std::string check_in, check_out; long long nights; };

// "YYYY-MM-DD" -> days since 1970-01-01 (UTC). Rejects impossible dates like 2026-02-30.
long long to_day_number(const std::string& iso) {
    int y = 0, m = 0, d = 0;
    if (std::sscanf(iso.c_str(), "%4d-%2d-%2d", &y, &m, &d) != 3)
        throw std::invalid_argument("Dates must use YYYY-MM-DD");
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = m - 1;
    tm.tm_mday = d;
    const std::time_t t = timegm(&tm);
    std::tm back{};
    gmtime_r(&t, &back);
    if (back.tm_year != y - 1900 || back.tm_mon != m - 1 || back.tm_mday != d)
        throw std::invalid_argument("Not a real calendar date: " + iso);
    return static_cast<long long>(t) / 86400;
}

Stay validate_stay(const std::string& in, const std::string& out, long long guests) {
    static const std::regex iso_re(R"([0-9]{4}-[0-9]{2}-[0-9]{2})");
    if (!std::regex_match(in, iso_re) || !std::regex_match(out, iso_re))
        throw std::invalid_argument("Dates must use YYYY-MM-DD");
    const long long in_day = to_day_number(in);
    const long long out_day = to_day_number(out);
    const long long today = static_cast<long long>(std::time(nullptr)) / 86400;
    if (in_day < today) throw std::invalid_argument("Check-in cannot be in the past");
    if (out_day <= in_day) throw std::invalid_argument("Check-out must be after check-in");
    if (out_day - in_day > 30) throw std::invalid_argument("Maximum stay is 30 nights");
    if (guests < 1 || guests > 10) throw std::invalid_argument("Guests must be between 1 and 10");
    return Stay{in, out, out_day - in_day};
}

// All money is integer paise (1 rupee = 100 paise). Binary floats never touch totals.
long long to_paise(double rupees) { return std::llround(rupees * 100.0); }

std::string money(long long paise) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld.%02lld", paise / 100, paise % 100);
    return buf;
}

struct Tariff { long long room_charge, booking_fee, tax, total; };

Tariff compute_tariff(long long nightly_rate_paise, long long nights) {
    Tariff t{};
    t.room_charge = nightly_rate_paise * nights;
    t.booking_fee = BOOKING_FEE_PAISE;
    t.tax = (t.room_charge * TAX_BASIS_POINTS + 5000) / 10000;  // round half up
    t.total = t.room_charge + t.booking_fee + t.tax;
    return t;
}

json tariff_json(const Tariff& t) {
    return json{{"room_charge", money(t.room_charge)}, {"booking_fee", money(t.booking_fee)},
                {"tax", money(t.tax)}, {"total", money(t.total)}};
}

// ------------------------------------------------------------ Validation
void validate_email(const std::string& email) {
    static const std::regex re(R"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})");
    if (email.size() > 255 || !std::regex_match(email, re))
        throw std::invalid_argument("Invalid email address");
}

void validate_phone(const std::string& phone) {
    static const std::regex re(R"(\+?[0-9]{10,15})");
    if (!std::regex_match(phone, re)) throw std::invalid_argument("Phone must have 10 to 15 digits");
}

bool luhn_ok(const std::string& digits) {
    int sum = 0;
    bool doubled = false;
    for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i) {
        int d = digits[i] - '0';
        if (doubled) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        doubled = !doubled;
    }
    return sum % 10 == 0;
}

std::string digits_only(std::string s) {
    s.erase(std::remove_if(s.begin(), s.end(),
            [](unsigned char c) { return std::isspace(c) || c == '-'; }), s.end());
    return s;
}

void validate_card(const std::string& number, const std::string& expiry, const std::string& cvv) {
    static const std::regex card_re(R"([0-9]{13,19})");
    static const std::regex expiry_re(R"((0[1-9]|1[0-2])/([0-9]{2}))");
    static const std::regex cvv_re(R"([0-9]{3,4})");

    if (!std::regex_match(number, card_re) || !luhn_ok(number))
        throw std::invalid_argument("Card number is invalid");

    std::smatch m;
    if (!std::regex_match(expiry, m, expiry_re))
        throw std::invalid_argument("Expiry must be in MM/YY format");
    const int month = std::stoi(m[1].str());
    const int year = 2000 + std::stoi(m[2].str());

    const std::time_t t = std::time(nullptr);
    std::tm now{};
    gmtime_r(&t, &now);
    if (year < now.tm_year + 1900 || (year == now.tm_year + 1900 && month < now.tm_mon + 1))
        throw std::invalid_argument("Card has expired");

    if (!std::regex_match(cvv, cvv_re))
        throw std::invalid_argument("CVV must be 3 or 4 digits");
}

// ------------------------------------------------------------ Payment gateway
struct GatewayReply { bool approved; std::string reference; };

// Stand-in for a PCI-compliant gateway SDK (Razorpay, Stripe, PayU). In production the
// gateway's own script tokenises the card in the browser, so the card never reaches
// this server. Test numbers: 4242424242424242 approves, 4000000000000002 declines.
GatewayReply gateway_charge(const std::string& card_number, long long amount_paise) {
    (void)amount_paise;
    const bool declined = card_number.size() >= 4 &&
                          card_number.compare(card_number.size() - 4, 4, "0002") == 0;
    return GatewayReply{!declined, random_hex(8)};
}

// ------------------------------------------------------------ Database layer
// sql::Connection objects are not thread-safe. Each request leases one connection
// exclusively and returns it when finished. The pool also caps concurrent DB sessions.
class ConnectionPool {
public:
    ConnectionPool(const std::string& url, const std::string& user,
                   const std::string& pass, const std::string& schema, std::size_t size) {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
        for (std::size_t i = 0; i < size; ++i) {
            std::unique_ptr<sql::Connection> c(driver->connect(url, user, pass));
            c->setSchema(schema);
            c->setTransactionIsolation(sql::TRANSACTION_READ_COMMITTED);
            idle_.push_back(std::move(c));
        }
    }

    std::unique_ptr<sql::Connection> acquire() {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this] { return !idle_.empty(); });
        auto c = std::move(idle_.back());
        idle_.pop_back();
        return c;
    }

    void release(std::unique_ptr<sql::Connection> c) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            idle_.push_back(std::move(c));
        }
        cv_.notify_one();
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<std::unique_ptr<sql::Connection>> idle_;
};

// RAII lease: the connection returns to the pool even if a handler throws.
class Lease {
public:
    explicit Lease(ConnectionPool& pool) : pool_(pool), conn_(pool.acquire()) {}
    ~Lease() { if (conn_) pool_.release(std::move(conn_)); }
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;

    sql::Connection* operator->() const { return conn_.get(); }
    sql::Connection* get() const { return conn_.get(); }

private:
    ConnectionPool& pool_;
    std::unique_ptr<sql::Connection> conn_;
};

// RAII transaction: rolls back automatically unless commit() has run.
class Transaction {
public:
    explicit Transaction(sql::Connection* c) : c_(c) { c_->setAutoCommit(false); }

    void commit() {
        c_->commit();
        done_ = true;
        c_->setAutoCommit(true);
    }

    ~Transaction() {
        if (!done_) {
            try { c_->rollback(); c_->setAutoCommit(true); } catch (...) {}
        }
    }

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

private:
    sql::Connection* c_;
    bool done_ = false;
};

long long last_insert_id(sql::Connection* c) {
    std::unique_ptr<sql::Statement> st(c->createStatement());
    std::unique_ptr<sql::ResultSet> rs(st->executeQuery("SELECT LAST_INSERT_ID()"));
    rs->next();
    return static_cast<long long>(rs->getInt(1));
}

// ------------------------------------------------------------ Error mapping
// Every handler body runs inside guard(), which turns exceptions into HTTP responses.
// Internal details go to stderr and are never sent to the client.
template <typename Fn>
void guard(httplib::Response& res, Fn&& fn) {
    try {
        fn();
    } catch (const HttpError& e) {
        send_error(res, e.status, e.message);
    } catch (const json::exception&) {
        send_error(res, 400, "Malformed or incomplete JSON body");
    } catch (const std::invalid_argument& e) {
        send_error(res, 422, e.what());
    } catch (const sql::SQLException& e) {
        if (std::string(e.getSQLState()) == "45000") {         // trigger guard fired
            send_error(res, 409, "Room already booked for the requested dates");
        } else {
            std::cerr << "[db] " << e.what() << " (code " << e.getErrorCode() << ")\n";
            send_error(res, 500, "Database error");
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] " << e.what() << "\n";
        send_error(res, 500, "Internal server error");
    }
}

std::string env_or(const char* name, const char* fallback) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string(fallback);
}

// ============================================================ Auth routes
void mount_auth_routes(httplib::Server& svr, ConnectionPool* pool) {

    // POST /api/auth/register  {full_name, email, phone, password}
    svr.Post("/api/auth/register", [pool](const httplib::Request& req, httplib::Response& res) {
        guard(res, [&] {
            const json body = json::parse(req.body);
            const std::string name     = body.at("full_name").get<std::string>();
            const std::string email    = body.at("email").get<std::string>();
            const std::string phone    = body.at("phone").get<std::string>();
            const std::string password = body.at("password").get<std::string>();

            if (name.size() < 2 || name.size() > 100)
                throw std::invalid_argument("Full name must be 2 to 100 characters");
            validate_email(email);
            validate_phone(phone);
            if (password.size() < 8)
                throw std::invalid_argument("Password must be at least 8 characters");

            const std::string hash = hash_password(password);   // deliberately slow (PBKDF2)

            Lease db(*pool);
            try {
                PS ins(db->prepareStatement(
                    "INSERT INTO CUSTOMERS (full_name, email, phone, password_hash) "
                    "VALUES (?, ?, ?, ?)"));
                ins->setString(1, name);
                ins->setString(2, email);
                ins->setString(3, phone);
                ins->setString(4, hash);
                ins->executeUpdate();
            } catch (const sql::SQLException& e) {
                if (e.getErrorCode() == 1062)                    // duplicate unique key
                    throw HttpError{409, "An account with this email already exists"};
                throw;
            }

            const long long id = last_insert_id(db.get());
            res.status = 201;
            res.set_content(json{{"customer_id", id}, {"full_name", name},
                                 {"token", issue_token(id)}}.dump(),
                            "application/json");
        });
    });

    // POST /api/auth/login  {email, password}
    svr.Post("/api/auth/login", [pool](const httplib::Request& req, httplib::Response& res) {
        guard(res, [&] {
            const json body = json::parse(req.body);
            const std::string email    = body.at("email").get<std::string>();
            const std::string password = body.at("password").get<std::string>();

            Lease db(*pool);
            PS ps(db->prepareStatement(
                "SELECT customer_id, full_name, password_hash FROM CUSTOMERS WHERE email = ?"));
            ps->setString(1, email);
            RS rs(ps->executeQuery());

            // Same message for unknown email and wrong password, so accounts cannot be enumerated.
            if (!rs->next() ||
                !verify_password(password, std::string(rs->getString("password_hash"))))
                throw HttpError{401, "Invalid email or password"};

            const long long id = rs->getInt("customer_id");
            res.set_content(json{{"token", issue_token(id)}, {"customer_id", id},
                                 {"full_name", std::string(rs->getString("full_name"))}}.dump(),
                            "application/json");
        });
    });
}

// ============================================================ Room routes
void mount_room_routes(httplib::Server& svr, ConnectionPool* pool) {

    // GET /api/rooms/search?check_in=YYYY-MM-DD&check_out=YYYY-MM-DD&guests=N
    svr.Get("/api/rooms/search", [pool](const httplib::Request& req, httplib::Response& res) {
        guard(res, [&] {
            const std::string g = req.get_param_value("guests");
            const long long guests = g.empty() ? 1 : std::stoll(g);
            const Stay stay = validate_stay(req.get_param_value("check_in"),
                                            req.get_param_value("check_out"), guests);

            Lease db(*pool);
            // Overlap-free room counts per type, using the same predicate as booking.
            PS ps(db->prepareStatement(
                "SELECT rt.room_type_id, rt.type_code, rt.type_name, rt.base_rate, "
                "       rt.max_occupancy, COUNT(r.room_id) AS available_rooms "
                "FROM ROOM_TYPES rt "
                "JOIN ROOMS r ON r.room_type_id = rt.room_type_id AND r.is_active = TRUE "
                "WHERE rt.max_occupancy >= ? "
                "  AND NOT EXISTS (SELECT 1 FROM RESERVATIONS b "
                "                  WHERE b.room_id = r.room_id "
                "                    AND b.status IN ('PENDING','CONFIRMED','CHECKED_IN') "
                "                    AND ? < b.check_out AND ? > b.check_in) "
                "GROUP BY rt.room_type_id, rt.type_code, rt.type_name, rt.base_rate, "
                "         rt.max_occupancy "
                "HAVING available_rooms > 0 "
                "ORDER BY rt.base_rate"));
            ps->setInt(1, static_cast<int>(guests));
            ps->setString(2, stay.check_in);
            ps->setString(3, stay.check_out);

            json rooms = json::array();
            RS rs(ps->executeQuery());
            while (rs->next()) {
                const long long rate = to_paise(rs->getDouble("base_rate"));
                rooms.push_back(json{
                    {"room_type_id",    rs->getInt("room_type_id")},
                    {"type_code",       std::string(rs->getString("type_code"))},
                    {"name",            std::string(rs->getString("type_name"))},
                    {"max_occupancy",   rs->getInt("max_occupancy")},
                    {"available_rooms", rs->getInt("available_rooms")},
                    {"nightly_rate",    money(rate)},
                    {"estimate",        tariff_json(compute_tariff(rate, stay.nights))}});
            }

            res.set_content(json{{"hotel", HOTEL_NAME},
                                 {"check_in", stay.check_in},
                                 {"check_out", stay.check_out},
                                 {"nights", stay.nights},
                                 {"rooms", rooms}}.dump(),
                            "application/json");
        });
    });
}

// ============================================================ Booking routes

// POST /api/bookings  {room_type_id, check_in, check_out, guests, contact_email, contact_phone}
// DELETE /api/bookings/{id}  soft cancel
void mount_booking_routes(httplib::Server& svr, ConnectionPool* pool) {

    svr.Post("/api/bookings", [pool](const httplib::Request& req, httplib::Response& res) {
        guard(res, [&] {
            const long long customer_id = require_customer(req);
            const json body = json::parse(req.body);

            const long long type_id = body.at("room_type_id").get<long long>();
            const long long guests  = body.at("guests").get<long long>();
            const std::string email = body.at("contact_email").get<std::string>();
            const std::string phone = body.at("contact_phone").get<std::string>();
            const Stay stay = validate_stay(body.at("check_in").get<std::string>(),
                                            body.at("check_out").get<std::string>(), guests);
            validate_email(email);
            validate_phone(phone);

            Lease db(*pool);
            Transaction tx(db.get());   // all steps below commit together, or not at all

            // S1: lock the room-type row. Concurrent bookings of this type queue here,
            //     so the availability check and the insert cannot interleave.
            long long nightly_rate = 0;
            int max_occupancy = 0;
            std::string type_name;
            {
                PS ps(db->prepareStatement(
                    "SELECT base_rate, max_occupancy, type_name "
                    "FROM ROOM_TYPES WHERE room_type_id = ? FOR UPDATE"));
                ps->setInt(1, static_cast<int>(type_id));
                RS rs(ps->executeQuery());
                if (!rs->next()) throw HttpError{404, "Room type not found"};
                nightly_rate  = to_paise(rs->getDouble("base_rate"));
                max_occupancy = rs->getInt("max_occupancy");
                type_name     = std::string(rs->getString("type_name"));
            }

            // S2: capacity guard.
            if (guests > max_occupancy)
                throw std::invalid_argument("This room type holds at most " +
                                            std::to_string(max_occupancy) + " guests");

            // S3: first active room of this type with no overlapping active booking.
            //     Overlap: (Requested_CheckIn < Existing_CheckOut) AND (Requested_CheckOut > Existing_CheckIn)
            long long room_id = 0;
            std::string room_number;
            {
                PS ps(db->prepareStatement(
                    "SELECT r.room_id, r.room_number FROM ROOMS r "
                    "WHERE r.room_type_id = ? AND r.is_active = TRUE "
                    "  AND NOT EXISTS (SELECT 1 FROM RESERVATIONS b "
                    "                  WHERE b.room_id = r.room_id "
                    "                    AND b.status IN ('PENDING','CONFIRMED','CHECKED_IN') "
                    "                    AND ? < b.check_out AND ? > b.check_in) "
                    "ORDER BY r.room_id LIMIT 1"));
                ps->setInt(1, static_cast<int>(type_id));
                ps->setString(2, stay.check_in);
                ps->setString(3, stay.check_out);
                RS rs(ps->executeQuery());
                if (!rs->next())
                    throw HttpError{409, "No rooms of this type are free for those dates"};
                room_id     = rs->getInt("room_id");
                room_number = std::string(rs->getString("room_number"));
            }

            // S4: insert the PENDING reservation. The no-overlap trigger is a second line of defence.
            long long reservation_id = 0;
            {
                PS ps(db->prepareStatement(
                    "INSERT INTO RESERVATIONS (customer_id, room_id, check_in, check_out, "
                    "num_guests, contact_email, contact_phone, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')"));
                ps->setInt(1, static_cast<int>(customer_id));
                ps->setInt(2, static_cast<int>(room_id));
                ps->setString(3, stay.check_in);
                ps->setString(4, stay.check_out);
                ps->setInt(5, static_cast<int>(guests));
                ps->setString(6, email);
                ps->setString(7, phone);
                ps->executeUpdate();
                reservation_id = last_insert_id(db.get());
            }

            // S5: billing row. Amounts are written as exact decimal strings, status PENDING
            //     until payment is captured.
            const Tariff t = compute_tariff(nightly_rate, stay.nights);
            {
                PS ps(db->prepareStatement(
                    "INSERT INTO PAYMENTS (reservation_id, transaction_ref, nights, room_charge, "
                    "booking_fee, tax_amount, total_amount, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')"));
                ps->setInt(1, static_cast<int>(reservation_id));
                ps->setString(2, random_hex(16));
                ps->setInt(3, static_cast<int>(stay.nights));
                ps->setString(4, money(t.room_charge));
                ps->setString(5, money(t.booking_fee));
                ps->setString(6, money(t.tax));
                ps->setString(7, money(t.total));
                ps->executeUpdate();
            }

            tx.commit();

            res.status = 201;
            res.set_content(json{
                {"reservation_id", reservation_id},
                {"status", "PENDING"},
                {"hold_seconds", HOLD_SECONDS},
                {"hotel", HOTEL_NAME},
                {"room_type", type_name},
                {"room_number", room_number},
                {"check_in", stay.check_in},
                {"check_out", stay.check_out},
                {"nights", stay.nights},
                {"guests", guests},
                {"nightly_rate", money(nightly_rate)},
                {"tariff", tariff_json(t)}}.dump(),
                "application/json");
        });
    });

    // DELETE /api/bookings/{id}  Soft cancel: the row is kept and its status becomes CANCELLED.
    svr.Delete(R"(/api/bookings/(\d+))", [pool](const httplib::Request& req, httplib::Response& res) {
        guard(res, [&] {
            const long long customer_id    = require_customer(req);
            const long long reservation_id = std::stoll(req.matches[1].str());

            Lease db(*pool);
            Transaction tx(db.get());

            // Lock order is always RESERVATIONS, then PAYMENTS, so transactions cannot deadlock.
            std::string status;
            {
                PS ps(db->prepareStatement(
                    "SELECT status FROM RESERVATIONS "
                    "WHERE reservation_id = ? AND customer_id = ? FOR UPDATE"));
                ps->setInt(1, static_cast<int>(reservation_id));
                ps->setInt(2, static_cast<int>(customer_id));
                RS rs(ps->executeQuery());
                if (!rs->next()) throw HttpError{404, "Booking not found"};
                status = std::string(rs->getString("status"));
            }
            if (status == "CANCELLED")
                throw HttpError{409, "This booking is already cancelled"};
            if (status == "CHECKED_IN" || status == "CHECKED_OUT")
                throw HttpError{409, "This stay has already started. Please contact reception."};

            {
                PS ps(db->prepareStatement(
                    "UPDATE RESERVATIONS SET status = 'CANCELLED', cancelled_at = NOW() "
                    "WHERE reservation_id = ?"));
                ps->setInt(1, static_cast<int>(reservation_id));
                ps->executeUpdate();
            }

            // Money side: a captured payment becomes REFUNDED (a real gateway refund call
            // belongs here; it is simulated). An unpaid hold closes as FAILED.
            const bool was_paid = (status == "CONFIRMED");
            {
                const std::string pay_sql = was_paid
                    ? "UPDATE PAYMENTS SET status = 'REFUNDED' "
                      "WHERE reservation_id = ? AND status = 'CAPTURED'"
                    : "UPDATE PAYMENTS SET status = 'FAILED' "
                      "WHERE reservation_id = ? AND status = 'PENDING'";
                PS ps(db->prepareStatement(pay_sql));
                ps->setInt(1, static_cast<int>(reservation_id));
                ps->executeUpdate();
            }

            tx.commit();
            res.set_content(json{{"reservation_id", reservation_id},
                                 {"status", "CANCELLED"},
                                 {"refund", std::string(was_paid ? "REFUNDED" : "NOT_REQUIRED")}}.dump(),
                            "application/json");
        });
    });
}

// ============================================================ Payment routes

// POST /api/payments  {reservation_id, card_number, expiry, cvv}
void mount_payment_routes(httplib::Server& svr, ConnectionPool* pool) {

    svr.Post("/api/payments", [pool](const httplib::Request& req, httplib::Response& res) {
        guard(res, [&] {
            const long long customer_id    = require_customer(req);
            const json body                = json::parse(req.body);
            const long long reservation_id = body.at("reservation_id").get<long long>();
            const std::string card_number  = digits_only(body.at("card_number").get<std::string>());
            const std::string expiry       = body.at("expiry").get<std::string>();
            const std::string cvv          = body.at("cvv").get<std::string>();

            // Card data is validated here and only the last four digits are ever stored.
            validate_card(card_number, expiry, cvv);

            Lease db(*pool);
            Transaction tx(db.get());

            // P1: lock this customer's reservation and confirm it is still awaiting payment
            //     within the hold window.
            {
                PS ps(db->prepareStatement(
                    "SELECT status, TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age_seconds "
                    "FROM RESERVATIONS WHERE reservation_id = ? AND customer_id = ? FOR UPDATE"));
                ps->setInt(1, static_cast<int>(reservation_id));
                ps->setInt(2, static_cast<int>(customer_id));
                RS rs(ps->executeQuery());
                if (!rs->next()) throw HttpError{404, "Booking not found"};
                if (std::string(rs->getString("status")) != "PENDING")
                    throw HttpError{409, "This booking is no longer awaiting payment"};
                if (rs->getInt("age_seconds") > HOLD_SECONDS)
                    throw HttpError{410, "The 15-minute hold has expired. Please search again."};
            }

            // P2: the pending bill. Amounts were fixed at booking time and are not recomputed.
            long long payment_id = 0;
            long long total_paise = 0;
            std::string txn_ref;
            {
                PS ps(db->prepareStatement(
                    "SELECT payment_id, transaction_ref, total_amount FROM PAYMENTS "
                    "WHERE reservation_id = ? AND status = 'PENDING' FOR UPDATE"));
                ps->setInt(1, static_cast<int>(reservation_id));
                RS rs(ps->executeQuery());
                if (!rs->next()) throw HttpError{409, "This bill has already been settled"};
                payment_id  = rs->getInt("payment_id");
                txn_ref     = std::string(rs->getString("transaction_ref"));
                total_paise = to_paise(rs->getDouble("total_amount"));
            }

            // P3: charge the card. The row locks stay held during this call, which is
            //     acceptable for one booking. Production would add a gateway timeout and an
            //     idempotency key.
            const GatewayReply gw = gateway_charge(card_number, total_paise);
            const std::string last4 = card_number.substr(card_number.size() - 4);

            if (!gw.approved) {
                // Record the declined attempt as its own FAILED row. The PENDING bill stays
                // open, so the guest can retry within the hold window.
                {
                    PS ps(db->prepareStatement(
                        "INSERT INTO PAYMENTS (reservation_id, transaction_ref, nights, room_charge, "
                        "booking_fee, tax_amount, total_amount, status, card_last4) "
                        "SELECT reservation_id, ?, nights, room_charge, booking_fee, tax_amount, "
                        "       total_amount, 'FAILED', ? FROM PAYMENTS WHERE payment_id = ?"));
                    ps->setString(1, random_hex(16));
                    ps->setString(2, last4);
                    ps->setInt(3, static_cast<int>(payment_id));
                    ps->executeUpdate();
                }
                tx.commit();   // keep the audit row even though the request fails
                throw HttpError{402, "Your card was declined. Please try another card."};
            }

            // P4: capture. The bill and the reservation change state in the same transaction.
            try {
                PS ps(db->prepareStatement(
                    "UPDATE PAYMENTS SET status = 'CAPTURED', card_last4 = ?, gateway_ref = ?, "
                    "captured_at = NOW() WHERE payment_id = ?"));
                ps->setString(1, last4);
                ps->setString(2, gw.reference);
                ps->setInt(3, static_cast<int>(payment_id));
                ps->executeUpdate();
            } catch (const sql::SQLException& e) {
                // uq_one_capture rejects a second captured payment for the same reservation.
                if (e.getErrorCode() == 1062)
                    throw HttpError{409, "This booking has already been paid"};
                throw;
            }
            {
                PS ps(db->prepareStatement(
                    "UPDATE RESERVATIONS SET status = 'CONFIRMED' WHERE reservation_id = ?"));
                ps->setInt(1, static_cast<int>(reservation_id));
                ps->executeUpdate();
            }

            tx.commit();

            res.set_content(json{{"reservation_id", reservation_id},
                                 {"status", "CONFIRMED"},
                                 {"transaction_ref", txn_ref},
                                 {"gateway_ref", gw.reference},
                                 {"card_last4", last4},
                                 {"amount_paid", money(total_paise)}}.dump(),
                            "application/json");
        });
    });
}

// ============================================================ Health and startup

// GET /api/health: used by uptime monitors. Returns 503 when the database is unreachable.
void mount_health_route(httplib::Server& svr, ConnectionPool* pool) {
    svr.Get("/api/health", [pool](const httplib::Request&, httplib::Response& res) {
        try {
            Lease db(*pool);
            std::unique_ptr<sql::Statement> st(db->createStatement());
            st->execute("SELECT 1");
            res.set_content(json{{"status", "ok"}, {"database", "up"}}.dump(), "application/json");
        } catch (const std::exception& e) {
            std::cerr << "[health] " << e.what() << "\n";
            send_error(res, 503, "Database unavailable");
        }
    });
}

int main() {
    const char* secret  = std::getenv("AUTH_SECRET");
    const char* db_pass = std::getenv("DB_PASS");
    if (!secret || std::string(secret).size() < 32) {
        std::cerr << "Set AUTH_SECRET to a random string of at least 32 characters.\n";
        return 1;
    }
    if (!db_pass) {
        std::cerr << "Set DB_PASS to the password of the hotel_app MySQL account.\n";
        return 1;
    }
    g_secret = secret;

    const std::string db_url  = env_or("DB_URL", "tcp://127.0.0.1:3306");
    const std::string db_user = env_or("DB_USER", "hotel_app");
    const std::string db_name = env_or("DB_NAME", "hotel_reservation");
    const int port = std::stoi(env_or("PORT", "8080"));

    try {
        ConnectionPool pool(db_url, db_user, db_pass, db_name, 8);

        httplib::Server svr;
        svr.set_payload_max_length(64 * 1024);    // reject oversized request bodies
        svr.set_mount_point("/", "./public");      // serves index.html, styles.css, app.js

        mount_auth_routes(svr, &pool);
        mount_room_routes(svr, &pool);
        mount_booking_routes(svr, &pool);
        mount_payment_routes(svr, &pool);
        mount_health_route(svr, &pool);

        std::cout << "Hotel reservation server running at http://localhost:" << port << "\n";
        if (!svr.listen("127.0.0.1", port)) {
            std::cerr << "Could not bind to port " << port << "\n";
            return 1;
        }
    } catch (const sql::SQLException& e) {
        std::cerr << "Database connection failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
