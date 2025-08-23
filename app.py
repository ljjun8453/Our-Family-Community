from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify, Response
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from db_config import get_connection, get_db_connection
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask import send_from_directory
from pathlib import Path
import pymysql.cursors
import requests
import db_config
import uuid
import json
import pymysql
import secrets
import subprocess
import re
import os


env_path = Path('/home/ljj3296/NAS/.env') # .env 파일 경로 명시적 지정
load_dotenv(dotenv_path=env_path) # 환경변수 로딩

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5000 * 1024 * 1024  # 5GB
app.secret_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)


app.config['DEBUG'] = True  # 디버그 모드 활성화


# 리버스프록시 진입시점의 실제 IP 반환
def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        # 여러 IP가 있을 경우 가장 앞의 것이 실제 사용자 IP
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


# 업로드 경로 설정
UPLOAD_FOLDER = '/mnt/usb/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 업로드 확장자 제한
ALLOWED_EXTENSIONS = {
    # 문서 관련
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'hwp', 'hwpx', 'txt', 'csv', 'md', 'log', 'json', 'xml',

    # 이미지
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp',

    # 압축
    'zip', '7z', 'rar', 'tar', 'gz', 'tgz',

    # 미디어
    'mp3', 'wav', 'mp4', 'mov', 'ogg', 'avi', 'webm'
}
# 업로드 확장자 검사
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# CSRF 보안토큰 부재시 생성후 세션 저장
#@app.before_request
#def ensure_csrf_token():
#    if '_csrf_token' not in session:
#        session['_csrf_token'] = generate_csrf()
#        print("세션 _csrf_token:", session.get('_csrf_token'))
#        print("요청 form csrf_token:", request.form.get('csrf_token'))


# CSRF 보안토큰 AJAX 요청에서의 헤더 허용
@app.after_request
def add_csrf_header(response):
    response.headers['X-CSRFToken'] = generate_csrf()
    return response

# CSRF 보안토큰 작동
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())


# 구글캡차 보안키 변수로 저장
RECAPTCHA_SECRET_KEY = '6LduRigrAAAAAJX8lYM9pDqqHwxyxYBudHeF4r9T'  # 발급받은 구글캡차 secret key

@app.route('/')  # 도메인/IP 접속 시 실행
def index():
    return render_template('index.html')  # templates/index.html 파일을 띄움



# userid 중복 확인
@csrf.exempt
@app.route('/check-duplicate', methods=['POST'])
def check_duplicate():
    data = request.get_json(force=True)
    userid = request.json.get('userid')

    if not userid:
        return jsonify({'error': '아이디가 비어 있습니다.'}), 400

    conn = db_config.get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS count FROM users WHERE userid = %s", (userid,))
            result = cursor.fetchone()
            return jsonify({ "isDuplicate": result['count'] > 0 }), 200
    except Exception as e:
        print(f"[ERROR] check-duplicate: {e}")
        return jsonify({'error': '서버 내부 오류 발생'}), 500
    finally:
        conn.close()



# 회원가입
@app.route('/register', methods=['POST'])
def register():
    # 캡차 인증
    recaptcha_response = request.form.get('g-recaptcha-response')
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = r.json()

    if not result.get('success'):
        return jsonify({'error': 'reCAPTCHA 인증에 실패했습니다.'}), 400

    # 캡차 통과시 회원가입 처리 계속
    name = request.form['name']
    userid = request.form['userid']
    password = request.form['password']
    email = request.form['email']
    birthdate = request.form['birthdate']
    privacy_agree = request.form.get('privacy_agree')
    agree_value = 1 if privacy_agree == 'on' else 0
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    user_uuid = str(uuid.uuid4())

    conn = db_config.get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO users (uuid, name, userid, password, email, birthdate, privacy_agree)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_uuid, name, userid, hashed_pw, email, birthdate, agree_value))
            conn.commit()

            return jsonify({'message': '회원가입이 완료되었습니다. 로그인 하세요!'}), 200
    except pymysql.IntegrityError as e:
        print(f"[ERROR] Duplicate entry: {e}")
        return jsonify({'error': '이미 존재하는 아이디 또는 이메일입니다.'}), 400
    except pymysql.MySQLError as e:
        print(f"[ERROR] MySQL 에러: {e}")
        return jsonify({'error': '서버 내부 오류가 발생했습니다.'}), 500
    finally:
        conn.close()



# 로그인
@csrf.exempt
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    userid = data.get('userid')
    password = data.get('password')

    conn = db_config.get_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE userid = %s AND deleted = 0"
            cursor.execute(sql, (userid,))
            user = cursor.fetchone()

            if user:
                db_password = user['password']
                if db_password and db_password.startswith('$2b$'):
                    if bcrypt.check_password_hash(db_password, password):
                        # 로그인 성공
                        session['userid'] = user['userid']
                        return jsonify({'success': True})
                    else:
                        # 비밀번호 틀림
                        return jsonify({'success': False, 'error': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401
                else:
                    # 암호화된 비밀번호 형식이 아님
                    return jsonify({'success': False, 'error': '잘못된 사용자 데이터입니다.'}), 400
            else:
                # 아이디 없음
                return jsonify({'success': False, 'error': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401
    finally:
        conn.close()



# 로그인 후 이동할 '홈'페이지
@app.route('/home')
def home():
    userid = session.get('userid')
    if not userid:
        return redirect(url_for('index'))

    conn = db_config.get_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # 공지사항 4개만
    cursor.execute('''
        SELECT f.id, f.title, f.author_id, u.name AS author_name, f.created_at
        FROM posts f
        JOIN users u ON f.author_id = u.userid
        WHERE f.deleted = 0 AND f.board_id = 2
        ORDER BY f.created_at DESC
        LIMIT 4
    ''')
    notice_posts = cursor.fetchall()

    # 자유게시판 10개만
    cursor.execute('''
        SELECT f.id, f.title, f.author_id, u.name AS author_name, f.created_at
        FROM posts f
        JOIN users u ON f.author_id = u.userid
        WHERE f.deleted = 0 AND f.board_id = 1
        ORDER BY f.created_at DESC
        LIMIT 10
    ''')
    free_posts = cursor.fetchall()

    # 가족 앨범 10개만
    cursor.execute('''
        SELECT f.id, f.title, f.author_id, u.name AS author_name, f.created_at
        FROM posts f
        JOIN users u ON f.author_id = u.userid
        WHERE f.deleted = 0 AND f.board_id = 3
        ORDER BY f.created_at DESC
        LIMIT 10
    ''')
    album_posts = cursor.fetchall()

    conn.close()

    return render_template('home.html', userid=userid, notice_posts=notice_posts, free_posts=free_posts, album_posts=album_posts)



# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))


# /login 경로만 CSRF 검사 제외
csrf.exempt(login)


# 자유게시판 + 페이지네이션
#@app.route('/free')
#def free():
#    page = request.args.get('page', 1, type=int)
#    per_page = 20
#    offset = (page - 1) * per_page

#    conn = db_config.get_connection()
#    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # 전체 게시글 수
#    cursor.execute('SELECT COUNT(*) AS total FROM posts WHERE deleted = 0')
#    total = cursor.fetchone()['total']

    # 현재 페이지에 보여줄 게시글 가져오기
#    cursor.execute('''
#        SELECT f.id, f.title, f.author_id, u.name AS author_name, f.created_at
#        FROM posts f
#        JOIN users u ON f.author_id = u.userid
#        WHERE f.deleted = 0 AND f.board_id = 1
#        ORDER BY f.created_at DESC
#        LIMIT %s OFFSET %s
#    ''', (per_page, offset))
#    posts = cursor.fetchall()
#    conn.close()

#    total_pages = (total + per_page - 1) // per_page

#    return render_template('free.html', posts=posts, page=page, total_pages=total_pages, userid=session['userid'])


# 기존 '/static/uploads'에서 USB '/mnt/usb/uploads'로 다이렉트 서빙
@app.route('/static/uploads/<path:filename>')
def serve_usb_file(filename):
    return send_from_directory('/mnt/usb/uploads', filename)


# 글쓰기 페이지 이동
#@app.route('/write')
#def write():
#    if 'userid' not in session:
#        flash('로그인이 필요합니다.', 'error')
#        return redirect(url_for('index'))  # 로그인 페이지로 보내기
#    return render_template('write.html', userid=session['userid'])


# Toast UI 에디터 사진삽입 DB주솟값 분리 저장 처리
@csrf.exempt
@app.route('/upload_image', methods=['POST'])
def upload_image():
    file = request.files.get('image')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': '잘못된 파일'}), 400

    ext = file.filename.rsplit('.', 1)[-1].lower()        # 확장자 유지(업로드된 확장자로)
    filename = secrets.token_hex(8) + '.' + ext
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(save_path)

    # 이미지 URL 반환 (Editor가 이걸 본문에 넣어줌)
    image_url = url_for('static', filename=f'uploads/{filename}')
    return jsonify({'url': image_url})


# 동영상 썸네일 추출 함수
def extract_thumbnail(video_path, output_image_path):
    print(f"[DEBUG] 썸네일 생성 중: {video_path} -> {output_image_path}")
    result = subprocess.run([
        'ffmpeg',
        '-y',
        '-i', video_path,
        '-ss', '00:00:05.000',  # 5초
        '-vframes', '1',
        output_image_path
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print("[ERROR] 썸네일 생성 실패!")
        print(result.stderr)
    else:
        print("[INFO] 썸네일 생성 성공!")




# 동영상 마커 -> video태그 변환 함수
def replace_video_markers(content_html):
    def replacer(match):
        filename = match.group(1)
        video_url = f"/static/uploads/{filename}"
        thumbnail_url = f"/static/uploads/{filename}.jpg"

        return f'''
<video controls style="max-width: 100%;" poster="{thumbnail_url}">
  <source src="{video_url}" type="video/mp4">
  브라우저가 동영상을 지원하지 않습니다.
</video>
'''
    return re.sub(r'\[ 동영상\s*:\s*([a-zA-Z0-9_\-\.]+\.mp4) \]', replacer, content_html)


# Toast UI 에디터 동영상삽입 DB주솟값 분리 저장 처리
@csrf.exempt
@app.route('/upload_video', methods=['POST'])
def upload_video():
    if 'video' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})

    file = request.files['video']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})

    if file and allowed_file(file.filename):
        original_name = secure_filename(file.filename)
        ext = original_name.rsplit('.', 1)[-1].lower()

        # hex로 저장될 이름
        hex_name = secrets.token_hex(8)
        saved_filename = hex_name + '.' + ext
        saved_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        file.save(saved_path)

        # ✅ 썸네일 파일 이름은 hex.jpg
        thumbnail_filename = hex_name + '.jpg'
        thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
        extract_thumbnail(saved_path, thumbnail_path)  # 이 부분 수정됨

        video_url = url_for('static', filename='uploads/' + saved_filename)
        thumbnail_url = url_for('static', filename='uploads/' + thumbnail_filename)
        return jsonify({
            'success': True,
            'videoUrl': video_url,
            'thumbnail_url': thumbnail_url,
            'stored_name': saved_filename,
            'original_name': original_name,
            'filename': saved_filename
        })

    return jsonify({'success': False, 'message': 'Invalid file type'})





# 글쓰기 완료 처리 (POST)
@app.route('/<board_name>/write', methods=['GET', 'POST'])
def write_post(board_name):
    # board_map을 상단에 정의 (게시판별 정보)
    board_map = {
        'free': {'title': '자유게시판', 'id': 1},
        'notice': {'title': '공지사항', 'id': 2},
        'album': {'title': '가족 앨범', 'id': 3},
        'event': {'title': '이벤트 소식', 'id': 4}
    }

    if board_name not in board_map:
        return "존재하지 않는 게시판입니다.", 404

    conn = db_config.get_connection()  # 데이터베이스 연결
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # 게시판별 ID 및 제목
    board_id = board_map[board_name]['id']
    board_title = board_map[board_name]['title']

    if request.method == 'GET':
        conn.close()
        return render_template('write.html', board_name=board_name, board_title=board_title, userid=session['userid'])

    # POST 요청 - 글쓰기 처리
    title = request.form['title']  # 제목
    content = request.form['content']  # 내용
    files = request.files.getlist('attachment')  # 첨부파일 처리

    # 게시글 내용이 비어있으면 처리하지 않음
    if not title or not content:
        flash("제목과 내용을 모두 입력해주세요.", 'warning')
        return render_template('write.html', board_name=board_name, board_title=board_title, userid=session['userid'])

    try:
        # 게시글 DB에 등록
        sql = """INSERT INTO posts (title, author, author_id, content, ip_address, board_id)
                 VALUES (%s, %s, %s, %s, %s, %s)"""
        cursor.execute(sql, (
            title,
            session['userid'],
            session['userid'],
            content,
            get_real_ip(),
            board_id  # 해당 게시판에 맞는 board_id
        ))
        post_id = cursor.lastrowid  # 방금 삽입된 게시글의 ID

        # 첨부파일 처리
        upload_dir = app.config['UPLOAD_FOLDER']  # 업로드 디렉토리 경로
        os.makedirs(upload_dir, exist_ok=True)  # 디렉토리가 없으면 생성

        # 첨부파일 저장 및 DB에 정보 삽입
        for file in files:
            if file and file.filename:
                # 파일 확장자 확인
                if not allowed_file(file.filename):  # 허용되지 않는 파일형식 체크
                    flash("허용되지 않은 파일 형식입니다.", "warning")
                    return render_template('write.html', userid=session['userid'], board_name=board_name, board_title=board_title)

                filename = secure_filename(file.filename)  # 안전한 파일명
                save_path = os.path.join(upload_dir, filename)  # 저장 경로

                print(f"파일 저장 경로: {save_path}")

                file.save(save_path)  # 파일 저장
                print(f"파일이 저장되었습니다: {filename}")

                # 첨부파일 DB에 저장
                file_sql = """
                    INSERT INTO attachments (board_id, post_id, file_name, file_path, file_size, file_type)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(file_sql, (
                    board_id,  # 첨부파일이 속한 게시판의 board_id
                    post_id,
                    filename,
                    save_path,
                    os.path.getsize(save_path),  # 파일 크기
                    file.content_type  # 파일 타입 (예: 'image/jpeg', 'video/mp4')
                ))

        conn.commit()  # 트랜잭션 커밋
    except Exception as e:
        print(f"[ERROR] 글 작성 중 오류: {e}")  # 오류 로그 출력
        conn.rollback()  # 오류 발생 시 롤백
        flash("글 작성 중 오류가 발생했습니다.", "danger")
        return render_template('write.html', userid=session['userid'], board_name=board_name, board_title=board_title)
    finally:
        conn.close()  # 데이터베이스 연결 종료

    flash("게시글이 등록되었습니다.", 'success')
    return redirect(url_for('board_list', board_name=board_name))






# 게시글 출력
@app.route('/<board_name>/view/<int:post_id>', methods=['GET'])
def view_post(board_name, post_id):
    # 디버깅: 요청된 게시글 ID 출력
    print(f"[DEBUG] 요청된 게시글 ID: {post_id}")

    try:
        conn = db_config.get_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        print(f"[DEBUG] 데이터베이스 연결 성공")
    except Exception as e:
        print(f"[ERROR] 데이터베이스 연결 오류: {e}")
        return "서버 오류 발생", 500

    # 게시판 이름에 따른 board_id 분기 처리
    board_map = {
        'free': {'title': '자유게시판', 'id': 1},
        'notice': {'title': '공지사항', 'id': 2},
        'album': {'title': '가족 앨범', 'id': 3},
        'event': {'title': '이벤트 소식', 'id': 4}
    }

    if board_name not in board_map:
        print(f"[ERROR] 잘못된 board_name: {board_name}")
        conn.close()
        return "존재하지 않는 게시판입니다.", 404

    board_id = board_map[board_name]['id']
    board_title = board_map[board_name]['title']
    print(f"[DEBUG] Board ID: {board_id}, Post ID: {post_id}")

    # 게시글을 찾기 위한 쿼리
    sql = """
        SELECT f.*, u.name AS author_name
        FROM posts f
        JOIN users u ON f.author_id = u.userid
        WHERE f.id = %s AND f.deleted = 0
    """
    print(f"[DEBUG] 게시글 조회 쿼리: {sql}, 파라미터: {post_id}")

    try:
        cursor.execute(sql, (post_id,))
        post = cursor.fetchone()

        # 디버깅: 쿼리 결과 출력
        print(f"[DEBUG] 게시글 조회 결과: {post}")

        if not post:
            print(f"[ERROR] 게시글을 찾을 수 없음: {post_id}")
            return "게시글을 찾을 수 없습니다.", 404

        # 조회수 증가
        update_sql = "UPDATE posts SET views = views + 1 WHERE id = %s"
        cursor.execute(update_sql, (post_id,))
        conn.commit()

        # 댓글 가져오기
        cursor.execute(""" 
            SELECT c.id, c.post_id, c.author_id, c.content, c.created_at, u.name AS author_name
            FROM comments c
            JOIN users u ON c.author_id = u.userid
            WHERE c.post_id = %s AND c.deleted = 0
        """, (post_id,))
        comments = cursor.fetchall()

        # 첨부파일 가져오기
        cursor.execute("""
            SELECT id, file_name, file_path, file_size, file_type
            FROM attachments
            WHERE post_id = %s
        """, (post_id,))
        attachments = cursor.fetchall()

        # 디버깅: 댓글과 첨부파일 조회 결과 출력
        print(f"[DEBUG] 댓글 조회 결과: {comments}")
        print(f"[DEBUG] 첨부파일 조회 결과: {attachments}")


    except Exception as e:
        print(f"[ERROR] 게시글 조회 중 오류: {e}")
        return "서버 오류 발생", 500

    finally:
        conn.close()

    # 정상적으로 게시글과 관련된 데이터가 준비되었으면 템플릿으로 전달
    return render_template('view.html', post=post, comments=comments, attachments=attachments, board_name=board_name, board_title=board_title, userid=session.get('userid'))








# 게시글 수정시 동영상 -> 마커텍스트로 재변환
def convert_video_html_to_marker(html):
    if not html:
        return ""  # 내용이 없으면 빈 문자열 반환

    try:
        # <video> 태그 안에서 src와 poster를 추출해서 마커로 변환
        def replace_video_tag(match):
            src = match.group(1)
            poster = match.group(2)
            return f'@[동영상]({src}){{{poster}}}'

        # 정규식: video 태그 내 source src, poster 속성 추출
        pattern = r'<video[^>]*poster="([^"]+)"[^>]*>\s*<source[^>]*src="([^"]+)"[^>]*>.*?</video>'
        return re.sub(pattern, replace_video_tag, html, flags=re.DOTALL)

    except Exception as e:
        # 변환 중 에러가 발생하면 그 오류를 로깅하고 빈 문자열 반환
        app.logger.error(f"Error in convert_video_html_to_marker: {e}")
        return html  # 원본 HTML 반환



# 게시글 수정완료시 마커텍스트 -> 동영상으로 재변환
def convert_marker_to_video_html(content):
    # 마커텍스트 @([동영상]) => <video>로 변환
    def replace_marker(match):
        src = match.group(1)
        poster = match.group(2)
        return f'<video controls style="max-width: 100%;" poster="{poster}"><source src="{src}" type="video/mp4">브라우저가 동영상을 지원하지 않습니다.</video>'

    # 마커텍스트 패턴: @[동영상](src){poster}
    pattern = r'@\[(동영상)\]\(([^)]+)\)\{([^\}]+)\}'
    return re.sub(pattern, replace_marker, content)





# 게시글 수정
@app.route('/<board_name>/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(board_name, post_id):
    board_map = {
        'free': {'title': '자유게시판', 'id': 1},
        'notice': {'title': '공지사항', 'id': 2},
        'album': {'title': '가족 앨범', 'id': 3},
        'event': {'title': '이벤트 소식', 'id': 4}
    }

    userid = session.get('userid')
    if not userid:
        return redirect(url_for('index'))  # 로그인하지 않았다면 index로 리다이렉트

    conn = get_db_connection()
    cursor = conn.cursor()

    # board_name을 사용하여 board_id 찾기
    cursor.execute("SELECT id FROM boards WHERE name = %s", (board_name,))
    board = cursor.fetchone()

    if not board:
        conn.close()
        return "게시판을 찾을 수 없습니다.", 404  # 게시판이 존재하지 않으면 404 응답

    board_id = board['id']

    # 게시글 가져오기
    cursor.execute("SELECT * FROM posts WHERE id = %s AND deleted = 0 AND board_id = %s", (post_id, board_id))
    post = cursor.fetchone()

    if not post or post['author_id'] != userid:
        conn.close()
        return "수정 권한이 없습니다.", 403  # 수정 권한이 없으면 403 응답

    # ✅ 영상 마커텍스트로 복원 (GET 요청 시에만 실행)
    if post['content']:
        post['content'] = convert_marker_to_video_html(post['content'])  # 마커텍스트 -> HTML로 변환
    else:
        post['content'] = ""

    if request.method == 'POST':
        new_title = request.form['title'].strip()
        new_content = request.form['content'].strip()

        # 빈 값에 대한 유효성 검사
        if not new_title or not new_content:
            return "제목과 내용을 모두 입력해주세요.", 400  # 제목과 내용이 없으면 400 응답

        cursor.execute("""
            UPDATE posts
            SET title = %s, content = %s, updated_at = NOW()
            WHERE id = %s AND board_id = %s
        """, (new_title, new_content, post_id, board_id))
        conn.commit()
        conn.close()

        return redirect(url_for('view_post', board_name=board_name, post_id=post_id))  # 수정 후 게시글 보기 페이지로 리다이렉트

    conn.close()
    return render_template('edit.html', post=post, board_title=board_map[board_name]['title'], board_name=board_name, userid=userid)  # GET 요청 시 수정 페이지로 렌더링



# 게시글 삭제(논리)
@app.route('/<board_name>/delete/<int:post_id>', methods=['POST'])
def delete_post(board_name, post_id):
    userid = session.get('userid')
    if not userid:
        flash("로그인 후 삭제할 수 있습니다.", 'warning')
        return redirect(url_for('login'))

    # board_map을 상단에 정의
    board_map = {
        'free': 1,      # 자유게시판
        'notice': 2,    # 공지사항
        'album': 3,     # 가족 앨범
        'event': 4      # 이벤트 소식
    }

    if board_name not in board_map:
        flash("존재하지 않는 게시판입니다.", 'danger')
        return redirect(url_for('home'))

    # 데이터베이스 연결
    conn = get_db_connection()
    cursor = conn.cursor()

    # 게시글 확인
    cursor.execute("""
        SELECT * FROM posts
        WHERE id = %s AND deleted = 0 AND board_id = %s
    """, (post_id, board_map[board_name]))

    post = cursor.fetchone()

    if not post or post['author_id'] != userid:
        conn.close()
        flash("삭제 권한이 없거나 존재하지 않는 게시글입니다.", 'danger')
        return redirect(url_for('board_list', board_name=board_name))

    # 논리 삭제 수행
    cursor.execute("""
        UPDATE posts
        SET deleted = 1, updated_at = NOW()
        WHERE id = %s AND board_id = %s
    """, (post_id, board_map[board_name]))
    conn.commit()
    conn.close()

    flash("게시글이 삭제되었습니다.", 'success')
    return redirect(url_for('board_list', board_name=board_name))




# 마이페이지
@app.route('/mypage', methods=['GET', 'POST'])
def mypage():
    if 'userid' not in session:
        return redirect(url_for('index'))

    userid = session['userid']

    conn = get_db_connection()
    cursor = conn.cursor()

    # 사용자 정보 가져오기
    cursor.execute("SELECT name, userid, email, birthdate FROM users WHERE userid = %s AND deleted = 0", (userid,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return redirect(url_for('index'))

    # 내가 쓴 글 가져오기 (삭제 안된 것만)
    cursor.execute("""
        SELECT id, title, board_id 
        FROM posts 
        WHERE author_id = %s AND deleted = 0 
        ORDER BY created_at DESC
    """, (userid,))
    posts = cursor.fetchall()

    # board_id → board_name 매핑 추가
    board_map = {
        1: 'free',
        2: 'notice',
        3: 'album',
        4: 'event'
    }
    for post in posts:
        post['board_name'] = board_map.get(post['board_id'], 'free')

    cursor.close()
    conn.close()

    return render_template('mypage.html', user=user, userid=userid, posts=posts)



# 마이페이지 비밀번호 변경
@app.route('/change_password', methods=['POST'])
def change_password():
    userid = session.get('userid')
    if not userid:
        return redirect(url_for('index'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE userid = %s", (userid,))
    user = cursor.fetchone()

    cursor.execute("SELECT * FROM posts WHERE author_id = %s AND deleted = 0 AND board_id = %s", (user['id'], 1))
    posts = cursor.fetchall()

    error_current = error_new = error_confirm = None

    if not user or not bcrypt.check_password_hash(user['password'], current_password):
        error_current = '현재 비밀번호가 일치하지 않습니다.'

    if new_password != confirm_password:
        error_confirm = '새 비밀번호가 일치하지 않습니다.'

    if error_current or error_new or error_confirm:
        conn.close()
        return render_template('mypage.html', user=user, posts=posts,
                               error_current=error_current,
                               error_new=error_new,
                               error_confirm=error_confirm)

    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute("UPDATE users SET password = %s WHERE userid = %s", (hashed_pw, userid))
    conn.commit()
    conn.close()

    session.clear()
    return render_template('password_changed.html')


# 마이페이지 비밀번호 변경시 현재 비밀번호 실시간 확인 AJAX
@csrf.exempt
@app.route('/check_current_password', methods=['POST'])
def check_current_password():
    if 'userid' not in session:
        return jsonify({'valid': False})

    data = request.get_json()
    current_password = data.get('current_password')

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT password FROM users WHERE userid = %s", (session['userid'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({'valid': False})

    is_valid = bcrypt.check_password_hash(user['password'], current_password)
    return jsonify({'valid': is_valid})


# 회원 탈퇴 (논리)
@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'userid' not in session:
        return redirect(url_for('index'))

    userid = session['userid']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE users SET deleted = 1 WHERE userid = %s", (userid,))
        conn.commit()
        session.clear()  # 세션 초기화 (자동 로그아웃)
        flash('회원 탈퇴가 완료되었습니다.')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"[ERROR] 회원 탈퇴 중 오류 발생: {e}")
        flash('회원 탈퇴 중 오류가 발생했습니다.')
        return redirect(url_for('mypage'))
    finally:
        cursor.close()
        conn.close()



# 게시글 더보기 목록
#@app.route('/<board_name>')
#def board_list(board_name):
#    board_map = {
#        'free': {'title': '자유게시판', 'id': 1},
#        'notice': {'title': '공지사항', 'id': 2},
#        'album': {'title': '가족 앨범', 'id': 3},
#        'event': {'title': '이벤트 소식', 'id': 4}
#    }
#    if board_name not in board_map:
#        return "존재하지 않는 게시판입니다.", 404

#    page = request.args.get('page', 1, type=int)
#    per_page = 20
#    offset = (page - 1) * per_page

#    conn = db_config.get_connection()
#    cursor = conn.cursor(pymysql.cursors.DictCursor)

#    board_id = board_map[board_name]['id']
#    board_title = board_map[board_name]['title']

#    cursor.execute("SELECT COUNT(*) AS total FROM posts WHERE deleted = 0 AND board_id = %s", (board_id,))
#    total = cursor.fetchone()['total']

#    cursor.execute('''
#        SELECT f.id, f.title, f.author_id, u.name AS author_name, f.created_at
#        FROM posts f
#        JOIN users u ON f.author_id = u.userid
#        WHERE f.deleted = 0 AND f.board_id = %s
#        ORDER BY f.created_at DESC
#        LIMIT %s OFFSET %s
#    ''', (board_id, per_page, offset))
#    posts = cursor.fetchall()

    # 앨범 게시판일 경우 썸네일 추가
#    if board_name == 'album':
#        for post in posts:
#            post['thumbnail_url'] = get_thumbnail(post['id'])

#    conn.close()

#    total_pages = (total + per_page - 1) // per_page

#    return render_template(
#        'board.html',
#        posts=posts,
#        page=page,
#        total_pages=total_pages,
#        board_name=board_name,
#        board_title=board_title,
#        userid=session['userid']
#    )

@app.route('/<board_name>')
def board_list(board_name):
    # board_map을 상단에 정의
    board_map = {
        'free': {'title': '자유게시판', 'id': 1},
        'notice': {'title': '공지사항', 'id': 2},
        'album': {'title': '가족 앨범', 'id': 3},
        'event': {'title': '이벤트 소식', 'id': 4}
    }

    if board_name not in board_map:
        return "존재하지 않는 게시판입니다.", 404

    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    conn = db_config.get_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    board_id = board_map[board_name]['id']
    board_title = board_map[board_name]['title']

    cursor.execute("SELECT COUNT(*) AS total FROM posts WHERE deleted = 0 AND board_id = %s", (board_id,))
    total = cursor.fetchone()['total']

    cursor.execute('''
        SELECT f.id, f.title, f.author_id, u.name AS author_name, f.created_at
        FROM posts f
        JOIN users u ON f.author_id = u.userid
        WHERE f.deleted = 0 AND f.board_id = %s
        ORDER BY f.created_at DESC
        LIMIT %s OFFSET %s
    ''', (board_id, per_page, offset))
    posts = cursor.fetchall()

    conn.close()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'board.html',
        posts=posts,
        page=page,
        total_pages=total_pages,
        board_name=board_name,
        board_title=board_title,
        userid=session['userid']
    )







# 댓글 작성
@app.route('/<board_name>/add_comment/<int:post_id>', methods=['POST'])
def add_comment(board_name, post_id):
    if 'userid' not in session:
        flash('로그인이 필요합니다.', 'error')
        return redirect(url_for('index'))

    content = request.form['content']
    author_id = session['userid']

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # 사용자 이름 가져오기
    cursor.execute("SELECT name FROM users WHERE userid = %s", (author_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash("유저 정보를 찾을 수 없습니다.", "error")
        return redirect(url_for('view_post', board_name=board_name, post_id=post_id))


    # 댓글 추가 후, 해당 게시글의 댓글 수를 1 증가
    cursor.execute("""
        UPDATE posts
        SET comments = comments + 1
        WHERE id = %s
    """, (post_id,))


    cursor.execute("""
        INSERT INTO comments (post_id, author_id, content)
        VALUES (%s, %s, %s)
    """, (post_id, author_id, content))
    conn.commit()
    conn.close()

    return redirect(url_for('view_post', board_name=board_name, post_id=post_id))




# 댓글 삭제 (논리 삭제)
@app.route('/<board_name>/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(board_name, comment_id):
    # 세션에서 사용자 ID 가져오기
    user_id = session.get('userid')
    if not user_id:
        flash("로그인 후 삭제할 수 있습니다.", 'warning')
        return redirect(url_for('login'))

    # 데이터베이스에서 댓글을 가져오기
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT post_id FROM comments WHERE id = %s", (comment_id,))
    comment = cursor.fetchone()

    if comment:
        post_id = comment['post_id']  # 해당 댓글이 속한 게시글의 ID

        # 댓글이 존재하고, 댓글 작성자가 본인일 경우에만 삭제 가능
        cursor.execute("SELECT * FROM comments WHERE id = %s AND post_id = %s", (comment_id, post_id))
        comment = cursor.fetchone()

        if comment and comment['author_id'] == user_id:
            # 논리 삭제 처리 (deleted 값을 1로 설정)
            cursor.execute("UPDATE comments SET deleted = 1 WHERE id = %s", (comment_id,))

            # 댓글 수 감소 처리 (게시글의 댓글 수를 1 감소)
            cursor.execute("""
                UPDATE posts
                SET comments = comments - 1
                WHERE id = %s
            """, (post_id,))

            conn.commit()
            flash("댓글이 삭제되었습니다.", 'success')
        else:
            flash("본인 댓글만 삭제할 수 있습니다.", 'danger')
    else:
        flash("해당 댓글을 찾을 수 없습니다.", 'danger')

    conn.close()
    return redirect(url_for('board_list', board_name=board_name))





# 404 커스텀 페이지
@app.errorhandler(404)
def not_found_error(error):
    return render_template('not_found_404.html'), 404


# 개발서버용
#if __name__ == '__main__':
#    app.run(host='0.0.0.0', port=5000, debug=True)
