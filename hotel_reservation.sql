-- =============================================================================
-- hotel_reservation.sql : Online Hotel Reservation System (3NF, MySQL 8.0+)
-- Run as administrator:  mysql -u root -p < hotel_reservation.sql
-- =============================================================================

DROP DATABASE IF EXISTS hotel_reservation;
CREATE DATABASE hotel_reservation CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE hotel_reservation;

-- Least-privilege application account. No DELETE or DROP rights:
-- cancellations are soft deletes (status = 'CANCELLED').
-- The C++ server connects over TCP to 127.0.0.1, so both host forms are granted.
CREATE USER IF NOT EXISTS 'hotel_app'@'localhost'  IDENTIFIED BY 'Change_This_Password_123!';
CREATE USER IF NOT EXISTS 'hotel_app'@'127.0.0.1'  IDENTIFIED BY 'Change_This_Password_123!';
GRANT SELECT, INSERT, UPDATE ON hotel_reservation.* TO 'hotel_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON hotel_reservation.* TO 'hotel_app'@'127.0.0.1';

-- ----------------------------------------------------------------------------
-- 1. ROOM_TYPES : tariff categories (rates in INR)
-- ----------------------------------------------------------------------------
CREATE TABLE ROOM_TYPES (
    room_type_id   INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    type_code      VARCHAR(10)     NOT NULL,
    type_name      VARCHAR(60)     NOT NULL,
    base_rate      DECIMAL(10,2)   NOT NULL,
    max_occupancy  TINYINT UNSIGNED NOT NULL,
    description    VARCHAR(255)    NULL,
    PRIMARY KEY (room_type_id),
    UNIQUE KEY uq_room_type_code (type_code),
    CONSTRAINT chk_rate_positive CHECK (base_rate > 0),
    CONSTRAINT chk_occupancy CHECK (max_occupancy BETWEEN 1 AND 10)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 2. ROOMS : physical rooms, each belonging to exactly one room type (1:N)
-- ----------------------------------------------------------------------------
CREATE TABLE ROOMS (
    room_id       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    room_number   VARCHAR(10)  NOT NULL,
    room_type_id  INT UNSIGNED NOT NULL,
    floor_no      TINYINT      NOT NULL,
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (room_id),
    UNIQUE KEY uq_room_number (room_number),
    KEY idx_rooms_type (room_type_id, is_active),
    CONSTRAINT fk_rooms_type FOREIGN KEY (room_type_id)
        REFERENCES ROOM_TYPES (room_type_id) ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 3. CUSTOMERS : guest accounts
-- ----------------------------------------------------------------------------
CREATE TABLE CUSTOMERS (
    customer_id    INT UNSIGNED NOT NULL AUTO_INCREMENT,
    full_name      VARCHAR(100) NOT NULL,
    email          VARCHAR(255) NOT NULL,
    phone          VARCHAR(16)  NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,          -- PBKDF2-SHA256, never plaintext
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (customer_id),
    UNIQUE KEY uq_customer_email (email)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 4. STAFF : Reception and Admin accounts (operational access)
-- ----------------------------------------------------------------------------
CREATE TABLE STAFF (
    staff_id       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    full_name      VARCHAR(100) NOT NULL,
    email          VARCHAR(255) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    role           ENUM('ADMIN','RECEPTIONIST') NOT NULL DEFAULT 'RECEPTIONIST',
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (staff_id),
    UNIQUE KEY uq_staff_email (email)
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 5. RESERVATIONS : 1:N from CUSTOMERS, N:1 to ROOMS, soft delete via status
-- ----------------------------------------------------------------------------
CREATE TABLE RESERVATIONS (
    reservation_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    customer_id    INT UNSIGNED NOT NULL,
    room_id        INT UNSIGNED NOT NULL,
    check_in       DATE         NOT NULL,
    check_out      DATE         NOT NULL,
    num_guests     TINYINT UNSIGNED NOT NULL,
    contact_email  VARCHAR(255) NOT NULL,
    contact_phone  VARCHAR(16)  NOT NULL,
    status         ENUM('PENDING','CONFIRMED','CHECKED_IN','CHECKED_OUT','CANCELLED')
                   NOT NULL DEFAULT 'PENDING',
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cancelled_at   TIMESTAMP    NULL DEFAULT NULL,
    PRIMARY KEY (reservation_id),
    KEY idx_res_overlap (room_id, status, check_in, check_out),
    KEY idx_res_customer (customer_id),
    CONSTRAINT chk_stay_length CHECK (check_out > check_in),
    CONSTRAINT fk_res_customer FOREIGN KEY (customer_id)
        REFERENCES CUSTOMERS (customer_id) ON DELETE RESTRICT,
    CONSTRAINT fk_res_room FOREIGN KEY (room_id)
        REFERENCES ROOMS (room_id) ON DELETE RESTRICT
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 6. PAYMENTS : billing ledger. 1:N from RESERVATIONS (retries are allowed).
-- ----------------------------------------------------------------------------
CREATE TABLE PAYMENTS (
    payment_id      INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    reservation_id  INT UNSIGNED  NOT NULL,
    transaction_ref CHAR(32)      NOT NULL,
    nights          SMALLINT UNSIGNED NOT NULL,
    room_charge     DECIMAL(10,2) NOT NULL,
    booking_fee     DECIMAL(10,2) NOT NULL,
    tax_amount      DECIMAL(10,2) NOT NULL,
    total_amount    DECIMAL(10,2) NOT NULL,
    status          ENUM('PENDING','CAPTURED','FAILED','REFUNDED') NOT NULL DEFAULT 'PENDING',
    card_last4      CHAR(4)       NULL,            -- only the last four digits are stored
    gateway_ref     VARCHAR(64)   NULL,
    created_at      TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    captured_at     TIMESTAMP     NULL DEFAULT NULL,
    -- Generated key: non-NULL only for CAPTURED rows. UNIQUE permits many failed
    -- or refunded attempts but at most ONE captured payment per reservation.
    captured_key    INT UNSIGNED AS (IF(status = 'CAPTURED', reservation_id, NULL)) STORED,
    PRIMARY KEY (payment_id),
    UNIQUE KEY uq_transaction_ref (transaction_ref),
    UNIQUE KEY uq_one_capture (captured_key),
    KEY idx_pay_reservation (reservation_id),
    CONSTRAINT chk_total CHECK (total_amount = room_charge + booking_fee + tax_amount),
    CONSTRAINT fk_pay_reservation FOREIGN KEY (reservation_id)
        REFERENCES RESERVATIONS (reservation_id) ON DELETE RESTRICT
) ENGINE=InnoDB;

-- ----------------------------------------------------------------------------
-- 7. Database-level double-booking guard (defence in depth)
-- ----------------------------------------------------------------------------
DELIMITER $$

CREATE TRIGGER trg_res_no_overlap_insert
BEFORE INSERT ON RESERVATIONS FOR EACH ROW
BEGIN
    IF NEW.status IN ('PENDING','CONFIRMED','CHECKED_IN') AND EXISTS (
        SELECT 1 FROM RESERVATIONS b
         WHERE b.room_id = NEW.room_id
           AND b.status IN ('PENDING','CONFIRMED','CHECKED_IN')
           AND NEW.check_in  < b.check_out
           AND NEW.check_out > b.check_in) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Room already booked for the requested dates';
    END IF;
END$$

CREATE TRIGGER trg_res_no_overlap_update
BEFORE UPDATE ON RESERVATIONS FOR EACH ROW
BEGIN
    IF NEW.status IN ('PENDING','CONFIRMED','CHECKED_IN') AND EXISTS (
        SELECT 1 FROM RESERVATIONS b
         WHERE b.room_id = NEW.room_id
           AND b.reservation_id <> NEW.reservation_id
           AND b.status IN ('PENDING','CONFIRMED','CHECKED_IN')
           AND NEW.check_in  < b.check_out
           AND NEW.check_out > b.check_in) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Room already booked for the requested dates';
    END IF;
END$$

-- Expire unpaid holds after 15 minutes so abandoned checkouts release inventory.
SET GLOBAL event_scheduler = ON;
CREATE EVENT IF NOT EXISTS ev_release_unpaid_holds
ON SCHEDULE EVERY 5 MINUTE
DO
BEGIN
    UPDATE PAYMENTS p
      JOIN RESERVATIONS r ON r.reservation_id = p.reservation_id
       SET p.status = 'FAILED'
     WHERE r.status = 'PENDING' AND p.status = 'PENDING'
       AND r.created_at < NOW() - INTERVAL 15 MINUTE;
    UPDATE RESERVATIONS
       SET status = 'CANCELLED', cancelled_at = NOW()
     WHERE status = 'PENDING'
       AND created_at < NOW() - INTERVAL 15 MINUTE;
END$$

DELIMITER ;

-- ----------------------------------------------------------------------------
-- 8. Seed data (rates in INR; tariffs are read by the server at booking time)
-- ----------------------------------------------------------------------------
INSERT INTO ROOM_TYPES (type_code, type_name, base_rate, max_occupancy, description) VALUES
 ('STD', 'Standard Room',   2500.00, 2, 'Queen bed, city view'),
 ('DLX', 'Deluxe Room',     4200.00, 3, 'King bed, balcony'),
 ('STE', 'Executive Suite', 7800.00, 4, 'Living area, lounge access');

INSERT INTO ROOMS (room_number, room_type_id, floor_no) VALUES
 ('101', 1, 1), ('102', 1, 1),
 ('201', 2, 2), ('202', 2, 2),
 ('301', 3, 3);

-- The reference booking transaction (Section 9 of the earlier draft) has been
-- removed. It inserted a reservation for customer_id = 1, but no customers exist
-- in the seed data. The C++ booking route in server.cpp implements the same
-- steps (lock room type, find free room, insert reservation, insert bill) as a
-- prepared-statement transaction.
