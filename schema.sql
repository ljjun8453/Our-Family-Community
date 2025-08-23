CREATE DATABASE IF NOT EXISTS family_community;
USE family_community;

-- ✅ 회원 테이블
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  uuid CHAR(36) NOT NULL UNIQUE,
  name VARCHAR(50) NOT NULL,
  userid VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  birthdate CHAR(8),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  privacy_agree TINYINT(1) NOT NULL DEFAULT 0,
  deleted TINYINT(1) DEFAULT 0
);

-- ✅ 게시판 메타 정보 테이블
CREATE TABLE IF NOT EXISTS boards (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ✅ 게시글 통합 테이블 (외래키 포함)
CREATE TABLE IF NOT EXISTS posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  author VARCHAR(100) NOT NULL,
  author_id VARCHAR(100) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  ip_address VARCHAR(45) NOT NULL,
  views INT DEFAULT 0,
  likes INT DEFAULT 0,
  comments INT DEFAULT 0,
  deleted TINYINT(1) DEFAULT 0,
  board_id INT DEFAULT NULL,
  CONSTRAINT fk_posts_board FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE SET NULL
);

-- ✅ 첨부파일 테이블
CREATE TABLE IF NOT EXISTS attachments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  board_type VARCHAR(50) NOT NULL,
  post_id INT NOT NULL,
  file_name VARCHAR(255) NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  file_size BIGINT DEFAULT 0,
  file_type VARCHAR(100),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 댓글 테이블
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT,  -- 댓글이 달린 게시글 ID
    user_id INT,  -- 댓글 작성자 ID
    content TEXT,  -- 댓글 내용
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 댓글 작성 시간
    FOREIGN KEY (post_id) REFERENCES posts(id),  -- 게시글과 댓글을 연결
    FOREIGN KEY (user_id) REFERENCES users(id)  -- 댓글 작성자와 사용자 테이블을 연결
);
