import jwt
import time
import hashlib
import base64
import qrcode
import secrets
import string
import pymysql
import os
import uuid
import re
import requests
import urllib3

from werkzeug.utils import secure_filename
from config import session_secret_key as key, db_config as db, google_ai_config
from google import genai
from google.genai import types
from PIL import Image
from io import BytesIO
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from flask import Flask, request, jsonify, send_from_directory, session, send_file
from datetime import datetime, timedelta
from io import BytesIO
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from bs4 import BeautifulSoup
import re

import firebase_admin
from firebase_admin import credentials

cred = credentials.Certificate("AFIGserviceAccountKey.json")
firebase_admin.initialize_app(cred)

# FCM 관리 모듈 import
import fcm_manager

# SSL 인증서 검증 경고 비활성화
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from flask_socketio import SocketIO, emit, join_room as socketio_join, leave_room as socketio_leave

# TLS 1.2 강제 어댑터 클래스
class Tls12HttpAdapter(HTTPAdapter):
    """TLS 1.2를 강제하는 HTTP 어댑터"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.load_default_certs()
        ctx.check_hostname = False
        ctx.verify_mode = 0  # ssl.CERT_NONE
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

ROLE_STUDENT = 0
ROLE_PROFESSOR = 1
ROLE_STAFF = 2

STATUS_PRESENT = "출석"
STATUS_ABSENT = "결석"
STATUS_LATE = "지각"


# DB 연결 및 커서 생성 함수
def conn_cur_create():
    conn = pymysql.connect(host=db.DB_HOST, port=db.DB_PORT, user=db.DB_USER, password=db.DB_PASSWORD, db=db.DB_DATABASE, charset='utf8')
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    return conn, cursor

app = Flask(__name__)
app.config['SECRET_KEY'] = key.KEY
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Flutter 앱에서 접근 가능
app.config['SESSION_COOKIE_SECURE'] = False  # 개발 중에는 False, 배포 시 True (HTTPS)
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
CORS(app, supports_credentials=True)  # 쿠키 전송 허용

# SocketIO 초기화
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    ping_timeout=60,
    ping_interval=25,
    manage_session=False  # Flask 세션 관리 비활성화
)

# 토큰 블랙리스트 (실제 운영에서는 Redis 등을 사용하는 것이 좋습니다)
# {token: expiry_timestamp} 형태로 저장
token_blacklist = {}

def clean_expired_tokens():
    """만료된 토큰을 블랙리스트에서 제거"""
    current_time = time.time()
    expired_tokens = [token for token, expiry in token_blacklist.items() if expiry < current_time]
    for token in expired_tokens:
        del token_blacklist[token]
    if expired_tokens:
        print(f"🧹 만료된 토큰 {len(expired_tokens)}개 삭제됨")

# --- 1. 로그인 및 JWT 발급 ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    print(f"🔐 로그인 시도: username={username}")

    sql = {
        0 : f"SELECT password, salt FROM students WHERE student_number = '{username}';",
        1 : f"SELECT password, salt FROM professors WHERE professor_number = '{username}';",
        2 : f"SELECT password, salt FROM staff WHERE staff_number = '{username}';"
           }
    # db에서 사용자 정보 확인
    try :
        conn, cur = conn_cur_create()
        for i in range(3): 
            cur.execute(sql[i])
            print("sql쿼리문실행중....")
            if (password_db := cur.fetchone()) is not None:
                # role 0: student, 1: professor, 2: staff
                role = i
                break
    finally:
        conn.close()
        
    if password_db is None:
        return jsonify({"message": "아이디가 존재하지 않습니다."}), 401
    elif hash_password(password, password_db['salt']) == password_db['password']:
        # 비밀번호가 올바르다.
        print(f"✅ 로그인 성공: user={username}, role={role}")
        
        # Access Token 페이로드 (24시간 유효기간)
        access_payload = {
            'username': username,
            'role': role,
            'type': 'access',
            'exp': datetime.now() + timedelta(hours=24)  # 24시간 유효기간
        }
        
        # Refresh Token 페이로드 (긴 유효기간)
        refresh_payload = {
            'username': username,
            'role': role,
            'type': 'refresh',
            'exp': datetime.now() + timedelta(days=7)  # 7일 유효기간
        }
        
        # JWT 토큰들 생성
        access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm='HS256')
        refresh_token = jwt.encode(refresh_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        print(f"🎫 새 토큰 발급: user={username}")
        print(f"   Access Token 전체: {access_token}")
        print(f"   블랙리스트에 있는지 확인: {access_token in token_blacklist}")
        print(f"   블랙리스트 크기: {len(token_blacklist)}")
        
        # 기존 소켓 연결 강제 종료 (중복 로그인 방지)
        if username in connected_users:
            old_sid = connected_users[username]
            print(f"⚠️ 기존 소켓 연결 발견: user={username}, old_sid={old_sid}")
            try:
                socketio.server.disconnect(old_sid)
                del connected_users[username]
                print(f"✅ 기존 소켓 연결 강제 종료됨")
            except Exception as e:
                print(f"❌ 소켓 종료 실패: {e}")
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 86400  # 24시간 (초 단위)
        }), 200
    else:
        print("비밀번호다름")
        return jsonify({"message": "비밀번호가 다릅니다."}), 401

# --- 토큰 갱신 ---
@app.route('/refresh', methods=['POST'])
def refresh_token():
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({"message": "Refresh token is missing"}), 401
    
    try:
        # 토큰이 블랙리스트에 있는지 확인
        if refresh_token in token_blacklist:
            return jsonify({"message": "Refresh token has been revoked"}), 401
        
        # 리프레시 토큰 검증
        payload = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # 토큰 타입 확인
        if payload.get('type') != 'refresh':
            return jsonify({"message": "Invalid token type"}), 401
        
        refresh_token_exp = datetime.fromtimestamp(payload['exp'])
        # 기본값을 설정하여 조건에 따라 값이 설정되지 않은 경우를 방지
        new_refresh_payload = None
        # 리프레시 토큰이 만료되기 1일 전부터만 갱신 허용
        if refresh_token_exp - datetime.now() < timedelta(days=1):
            new_refresh_payload = {
                'username': payload['username'],
                'role': payload['role'],
                'type': 'refresh',
                'exp': datetime.now() + timedelta(days=7)  # 7일 유효기간
            }
        
        # 새로운 액세스 토큰 생성
        new_access_payload = {
            'username': payload['username'],
            'role': payload['role'],
            'type': 'access',
            'exp': datetime.now() + timedelta(hours=24)  # 24시간 유효기간
        }
        
        new_access_token = jwt.encode(new_access_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        if new_refresh_payload:
            new_refresh_token = jwt.encode(new_refresh_payload, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": 86400  # 24시간 (초 단위)
            }), 200
        else:
            return jsonify({
                "access_token": new_access_token,
                "refresh_token": None,
                "token_type": "Bearer",
                "expires_in": 86400  # 24시간 (초 단위)
            }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Refresh token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid refresh token"}), 401

# --- 로그아웃 ---
@app.route('/logout', methods=['POST'])
def logout():
    
    payload, error = require_jwt()  # JWT 검증 (역할 제한 없음)
    if error or not payload:
        # error is a tuple: (response, status_code)
        response, status_code = error
        return response, status_code
    
    
    # JSON 데이터 안전하게 파싱
    try:
        data = request.get_json()
        if data is None:
            data = {}
    except Exception as e:
        print(f"JSON 파싱 오류: {e}")
        data = {}
    
    # Authorization 헤더에서 현재 사용 중인 토큰 추출
    auth_header = request.headers.get('Authorization')
    current_access_token = None
    if auth_header and auth_header.startswith('Bearer '):
        current_access_token = auth_header.split(' ', 1)[1]
    
    # 토큰들 수집 (body에서 또는 header에서)
    access_token = data.get('access_token') or current_access_token
    refresh_token = data.get('refresh_token')
    
    print(f"🚪 로그아웃: user={payload.get('username')}")
    print(f"   Access Token 전체: {access_token if access_token else 'None'}")
    print(f"   Refresh Token 전체: {refresh_token if refresh_token else 'None'}")
    print(f"   블랙리스트 추가 전 크기: {len(token_blacklist)}")
    
    # 만료된 토큰 정리
    clean_expired_tokens()
    
    # 두 토큰을 블랙리스트에 추가 (만료 시간과 함께)
    if access_token:
        # Access Token의 만료 시간 추출
        try:
            token_payload = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
            expiry = token_payload.get('exp', time.time() + 86400)  # 기본 24시간
            token_blacklist[access_token] = expiry
            print(f"   ✅ 액세스 토큰 블랙리스트 추가됨 (만료: {datetime.fromtimestamp(expiry).isoformat()})")
        except:
            # 디코딩 실패 시 24시간 후 만료로 설정
            token_blacklist[access_token] = time.time() + 86400
            print(f"   ✅ 액세스 토큰 블랙리스트 추가됨 (기본 만료시간)")
    
    if refresh_token:
        # Refresh Token의 만료 시간 추출
        try:
            token_payload = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_exp": False})
            expiry = token_payload.get('exp', time.time() + 604800)  # 기본 7일
            token_blacklist[refresh_token] = expiry
            print(f"   ✅ 리프레시 토큰 블랙리스트 추가됨 (만료: {datetime.fromtimestamp(expiry).isoformat()})")
        except:
            # 디코딩 실패 시 7일 후 만료로 설정
            token_blacklist[refresh_token] = time.time() + 604800
            print(f"   ✅ 리프레시 토큰 블랙리스트 추가됨 (기본 만료시간)")
    
    print(f"   블랙리스트 추가 후 크기: {len(token_blacklist)}")
    
    # FCM 토큰 삭제 (선택적 - 클라이언트에서 device_token 전달 시, 학생만)
    device_token = data.get('device_token')
    user_role = payload.get('role')
    
    if device_token and user_role == ROLE_STUDENT:  # 학생인 경우만
        try:
            conn, cur = conn_cur_create()
            sql = "DELETE FROM fcm_tokens WHERE student_number = %s AND device_token = %s;"
            cur.execute(sql, (payload.get('username'), device_token))
            conn.commit()
            deleted_count = cur.rowcount
            conn.close()
            
            if deleted_count > 0:
                print(f"   🗑️ FCM 토큰 자동 삭제: 학생={payload.get('username')}, token={device_token[:20]}...")
        except Exception as fcm_error:
            print(f"   ⚠️ FCM 토큰 삭제 실패 (로그아웃은 성공): {fcm_error}")
    
    return jsonify({"message": "Successfully logged out"}), 200

def hash_password(password: str, salt: str) -> str:
    """
    비밀번호와 salt를 합쳐 SHA-256으로 암호화된 문자열을 반환합니다.
    """
    combined = password + salt
    hashed = hashlib.sha256(combined.encode()).hexdigest()
    return hashed

def generate_salt(length: int = 32) -> str:
    """
    암호학적으로 안전한 랜덤 salt 문자열을 생성합니다.
    DB varchar(64)에 맞춰 기본 길이는 64입니다.
    """
    alphabet = string.ascii_letters + string.digits
    salt = ''.join(secrets.choice(alphabet) for _ in range(length))
    return salt

@app.route('/lectures', methods=['GET'])
def get_lectures():
    # 교수/학생 모두 사용 가능하도록 역할 제한 없이 인증만 수행
    payload, error = require_jwt()  # JWT 검증 (역할 제한 없음)
    if error or not payload:
        # error is a tuple: (response, status_code)
        response, status_code = error
        return response, status_code

    role = payload['role']
    username = payload['username']

    # 학기 계산 공통 로직
    year = datetime.now().year
    semester = 1 if datetime.now().month < 7 else 2

    try:
        conn, cur = conn_cur_create()

        if role == ROLE_PROFESSOR:
            # 교수: 본인이 담당하는 강의 목록
            sql = (
                "SELECT l.id, s.`name`, l.`schedule` "
                "FROM lectures l "
                "JOIN subjects s ON l.subject_code = s.subject_code "
                "WHERE l.professor_number=%s AND l.`year`=%s AND l.semester=%s;"
            )
            cur.execute(sql, (username, year, semester))
            lectures = cur.fetchall()
            return jsonify(lectures)

        elif role == ROLE_STUDENT:
            sql = (
                "SELECT l.id, s.`name`, l.`schedule`, p.`name` AS professor_name "
                "FROM enrollments e "
                "JOIN lectures l ON e.lecture_id = l.id "
                "JOIN subjects s ON l.subject_code = s.subject_code "
                "JOIN professors p ON l.professor_number = p.professor_number "
                "WHERE e.student_number=%s "
                "AND l.`year`=%s AND l.semester=%s;"
            )
            cur.execute(sql, (username, year, semester))
            lectures = cur.fetchall()
            print(lectures)
            return jsonify(lectures)

        else:
            # 그 외 역할은 제한
            return jsonify({"message": "Permission denied"}), 403

    finally:
        conn.close()

@app.route('/assignments', methods=['GET'])
def get_assignments():
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error or not payload:
        return error
    
    lecture_id = request.args.get('lecture_id')
    include_past = request.args.get('include_past', 'false').lower() == 'true'
    
    if not lecture_id:
        return jsonify({"message": "lecture_id is required"}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        date_filter = "" if include_past else "AND a.due_date >= CURDATE()"
        
        sql = (
            "SELECT a.id, a.description, a.due_date "
            "FROM assignments a "
            f"WHERE a.lecture_id = {lecture_id} {date_filter} "
            "ORDER BY a.due_date;"
        )
        cur.execute(sql)
        assignments = cur.fetchall()
        print(assignments)
        
        return jsonify(assignments)
    finally:
        conn.close()


# --- 학생 정보 조회 ---
@app.route('/students/me', methods=['GET'])
def get_student_info():
    """로그인한 학생의 정보를 반환합니다."""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 학생 정보 조회 (departments 테이블 조인하여 degree_type 가져오기)
        sql = """
            SELECT 
                s.student_number, 
                s.name, 
                s.nickname, 
                s.department_name, 
                s.grade,
                s.admission_date,
                s.email, 
                s.phone_number,
                s.address,
                s.parents_name,
                s.parents_phone_number,
                s.academic_status,
                s.account_number,
                s.is_anonymous,
                d.degree_type
            FROM students s
            JOIN departments d ON s.department_code = d.department_code
            WHERE s.student_number = %s;
        """
        cur.execute(sql, (student_number,))
        student = cur.fetchone()
        
        if not student:
            return jsonify({"message": "학생 정보를 찾을 수 없습니다."}), 404
        
        # 닉네임이 빈 문자열이면 None으로 처리
        nickname = student['nickname']
        if nickname is not None and nickname.strip() == '':
            nickname = None
        
        # 응답 데이터 구성
        return jsonify({
            "student_number": student['student_number'],
            "name": student['name'],
            "nickname": nickname,
            "major": student['department_name'], # major -> department_name
            "grade": student['grade'],
            "admission_date": student['admission_date'].isoformat() if student['admission_date'] else None,
            "email": student['email'],
            "phone_number": student['phone_number'],
            "address": student['address'],
            "parents_name": student['parents_name'],
            "parents_phone_number": student['parents_phone_number'],
            "academic_status": student['academic_status'],
            "account_number": student['account_number'],
            "is_anonymous": 1 if student['is_anonymous'] == 1 else 0,
            "degree_type": student['degree_type']  # 2 또는 3
        }), 200
        
    finally:
        conn.close()


@app.route('/students/me', methods=['PUT'])
def update_student_info():
    """로그인한 학생의 정보를 수정합니다."""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    data = request.get_json()
    
    # 수정 가능한 필드만 추출
    nickname = data.get('nickname')
    email = data.get('email')
    phone = data.get('phone_number')  # 클라이언트에서 phone으로 보낼 수도 있음
    if not phone:
        phone = data.get('phone')
    address = data.get('address')
    guardian_name = data.get('guardian_name')
    if not guardian_name:
        guardian_name = data.get('parents_name')
    guardian_phone = data.get('guardian_phone')
    if not guardian_phone:
        guardian_phone = data.get('parents_phone_number')
    account_number = data.get('account_number')
    is_anonymous = data.get('is_anonymous', 1)  # 기본값 1 (익명)
    
    # 이메일 형식 검증 (선택 사항)
    if email:
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({"error": "Invalid email format"}), 400
    
    conn = None
    try:
        conn, cur = conn_cur_create()
        
        # 업데이트할 필드들을 동적으로 구성
        update_fields = []
        update_values = []
        
        if nickname is not None:
            update_fields.append("nickname = %s")
            update_values.append(nickname)
        
        if email is not None:
            update_fields.append("email = %s")
            update_values.append(email)
        
        if phone is not None:
            update_fields.append("phone_number = %s")
            update_values.append(phone)
        
        if address is not None:
            update_fields.append("address = %s")
            update_values.append(address)
        
        if guardian_name is not None:
            update_fields.append("parents_name = %s")
            update_values.append(guardian_name)
        
        if guardian_phone is not None:
            update_fields.append("parents_phone_number = %s")
            update_values.append(guardian_phone)
        
        if account_number is not None:
            update_fields.append("account_number = %s")
            update_values.append(account_number)
        
        if is_anonymous is not None:
            update_fields.append("is_anonymous = %s")
            update_values.append(1 if is_anonymous else 0)
        
        # 업데이트할 필드가 없으면 에러
        if not update_fields:
            return jsonify({"error": "No fields to update"}), 400
        
        # SQL 쿼리 구성
        update_values.append(student_number)
        sql = f"""
            UPDATE students 
            SET {', '.join(update_fields)}
            WHERE student_number = %s
        """
        
        cur.execute(sql, tuple(update_values))
        conn.commit()
        
        print(f"✅ 학생 정보 수정 완료: {student_number}")
        print(f"   수정된 필드: {', '.join([f.split(' = ')[0] for f in update_fields])}")
        
        return jsonify({"message": "정보가 수정되었습니다"}), 200
        
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"❌ 학생 정보 수정 에러: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()


def require_jwt(role=None):
    auth_header = request.headers.get('Authorization')
    print(auth_header)
    if not auth_header:
        return None, (jsonify({"message": "Authorization header is missing"}), 401)
    
    # Bearer 토큰 형식 확인
    try:
        token_type, token = auth_header.split(' ', 1)
        if token_type.lower() != 'bearer':
            return None, (jsonify({"message": "Invalid token type"}), 401)
    except ValueError:
        return None, (jsonify({"message": "Invalid authorization header format"}), 401)
    
    try:
        # 토큰이 블랙리스트에 있는지 확인
        if token in token_blacklist:
            return None, (jsonify({"message": "Token has been revoked"}), 401)
        
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        # 액세스 토큰인지 확인
        if payload.get('type') != 'access':
            return None, (jsonify({"message": "Invalid token type"}), 401)
        
        if role is not None and payload.get('role') != role:
            return None, (jsonify({"message": "Permission denied"}), 403)
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, (jsonify({"message": "Access token has expired"}), 401)

def decode_jwt_simple(token):
    """Socket.IO용 간단한 JWT 디코드 함수"""
    try:
        token_prefix = token[:30] if len(token) > 30 else token
        
        # 만료된 토큰 정리
        clean_expired_tokens()
        
        if token in token_blacklist:
            print(f"❌ 토큰 블랙리스트: {token_prefix}...")
            print(f"   블랙리스트 크기: {len(token_blacklist)}")
            print(f"   만료 시간: {datetime.fromtimestamp(token_blacklist[token]).isoformat()}")
            return None
        
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        if payload.get('type') != 'access':
            print(f"❌ 토큰 타입 오류: {payload.get('type')} (expected: access)")
            return None
        
        print(f"✅ JWT 검증 성공: user={payload.get('username')}, role={payload.get('role')}")
        print(f"   Token: {token_prefix}...")
        return payload
    except jwt.ExpiredSignatureError:
        print(f"❌ 토큰 만료: {token_prefix}...")
        return None
    except jwt.InvalidTokenError as e:
        print(f"❌ 잘못된 토큰 형식: {str(e)}")
        print(f"   Token: {token_prefix}...")
        return None

# --- 2. 교수: QR 코드 생성 (JWT 인증 필요) ---
@app.route('/professor/start-attendance', methods=['POST'])
def start_attendance():
    
    payload, error = require_jwt(role=ROLE_PROFESSOR)  # JWT 검증
    if error:
        return error
    lecture_id = request.get_json().get('lectureId')
    lecture_schedule = request.get_json().get('lectureSchedule') #월 10:00-11:50
    
    # 강의 10분전부터 강의 끝나는 시간 까지만 출결 시작 가능. 그 전엔 불가능.
    # if lecture_schedule:
    #     day_map = {'월':0, '화':1, '수':2, '목':3, '금':4, '토':5, '일':6}
    #     day_str, time_str = lecture_schedule.split()
    #     start_time_str, end_time_str = time_str.split('-')
    #     start_hour, start_minute = map(int, start_time_str.split(':'))
    #     end_hour, end_minute = map(int, end_time_str.split(':'))
        
    #     now = datetime.now()
    #     lecture_day = day_map.get(day_str)
    #     if lecture_day is None:
    #         return jsonify({"message": "Invalid lecture schedule format"}), 400
        
    #     # 이번주 해당 요일 날짜 계산
    #     days_ahead = lecture_day - now.weekday()
    #     if days_ahead < 0:  # 이미 지난 요일이면 다음주로
    #         days_ahead += 7
    #     lecture_date = now + timedelta(days=days_ahead)
        
    #     lecture_start = lecture_date.replace(hour=start_hour, minute=start_minute, second=0, microsecond=0) - timedelta(minutes=10)
    #     lecture_end = lecture_date.replace(hour=end_hour, minute=end_minute, second=0, microsecond=0)
        
    #     if not (lecture_start <= now <= lecture_end):
    #         print("출결 불가능 시간")
    #         return jsonify({"message": "출결은 강의 시작 10분 전부터 강의 종료 시각까지 가능합니다."}), 400
    
    
    # --- JWT 인증 성공 후 QR 생성 로직 (이전과 동일) ---
    timestamp = str(time.time())
    raw_data = f"{lecture_id}:{timestamp}"
    qr_token = hashlib.sha256((raw_data + app.config['SECRET_KEY']).encode()).hexdigest()
    qr_data = f"{raw_data}:{qr_token}"
    print(qr_data)

    img = qrcode.make(qr_data)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return jsonify({"qr_code": img_base64})


# --- 3. 학생: 출결 확인 (JWT 인증 필요) ---
@app.route('/student/check-attendance', methods=['GET', 'POST'])
def check_attendance():
    payload, error = require_jwt(role=ROLE_STUDENT)  # JWT 검증
    if error:
        return error
        
    # JWT에서 학생 ID를 직접 가져와 사용 (더 안전함)
    student_number = payload['username']
    
    if request.method == 'GET':
        # GET 요청: 출석 정보 조회
        lecture_id = request.args.get('lecture_id')
        attendance_date = request.args.get('attendance_date')  # YYYY-MM-DD 형식
        print(attendance_date)
        
        if not lecture_id:
            return jsonify({"message": "lecture_id parameter is required"}), 400
        
        try:
            conn, cur = conn_cur_create()
            
            if attendance_date:
                # 특정 날짜의 출석 정보 조회
                check_sql = f"SELECT status FROM attendances WHERE student_number='{student_number}' AND lecture_id={lecture_id} AND attendance_date = '{attendance_date}';"
            else:
                # 해당 강의의 모든 출석 정보 조회
                check_sql = f"SELECT status FROM attendances WHERE student_number='{student_number}' AND lecture_id={lecture_id} AND attendance_date = CURDATE();"
            
            cur.execute(check_sql)
            attendance_record = cur.fetchall()
            
            if not attendance_record:
                return jsonify({
                    "message": "출석 기록이 없습니다.",
                    "student_number": student_number,
                    "lecture_id": lecture_id,
                    "status": None
                }), 200
            
            # 첫 번째 레코드의 status 값을 추출
            status = attendance_record[0]['status'] if attendance_record else None
            
            return jsonify({
                "student_number": student_number,
                "lecture_id": lecture_id,
                "status": status
            }), 200
            
        finally:
            conn.close()
    
    elif request.method == 'POST':
        # POST 요청: QR 데이터로 출석 처리
        qr_data = request.get_json().get('qr_data')
        
        if not qr_data:
            return jsonify({"message": "qr_data is required"}), 400
        
        lecture_id, timestamp_str, received_qr_token = qr_data.split(':')
        
        # 시간 유효성 검사 (6000초)
        if time.time() - float(timestamp_str) > 6000:
            return jsonify({"message": "QR Code has expired"}), 400
            
        # QR 데이터 토큰 유효성 검사
        raw_data = f"{lecture_id}:{timestamp_str}"
        expected_qr_token = hashlib.sha256((raw_data + app.config['SECRET_KEY']).encode()).hexdigest()

        if received_qr_token != expected_qr_token:
            return jsonify({"message": "Invalid QR Code"}), 400
            
        # QR 코드 생성 시점을 기준으로 실제 강의 날짜 계산
        qr_generated_time = datetime.fromtimestamp(float(timestamp_str))
        lecture_date = qr_generated_time.date()  # QR 생성 시점의 날짜를 강의 날짜로 사용
        
        print(f"출석 요청: 학번 {student_number}, 강의 ID {lecture_id}, 강의 날짜 {lecture_date}")
        
        # 강의 날짜 기준으로 출결 기록 확인 및 저장
        try:
            conn, cur = conn_cur_create()
            # 해당 강의 날짜에 이미 출결 기록이 있는지 확인
            check_sql = f"SELECT status FROM attendances WHERE student_number='{student_number}' AND lecture_id={lecture_id} AND attendance_date = '{lecture_date}';"
            cur.execute(check_sql)
            existing_record = cur.fetchone()
            
            if existing_record is not None:
                print("스테이터스 출력" + existing_record['status'])
                return jsonify({"message": f"{lecture_date} 강의에 이미 출결이 기록되어 있습니다. (현재 상태: {existing_record['status']})"}), 400
            
            # 강의 날짜로 출석 기록 저장
            insert_sql = f"INSERT INTO attendances (student_number, lecture_id, attendance_date, status) VALUES ('{student_number}', '{lecture_id}', '{lecture_date}', '{STATUS_PRESENT}');"
            cur.execute(insert_sql)
            conn.commit()
            
            print(f"출석 처리 완료: 학번 {student_number}, 강의 ID {lecture_id}, 날짜 {lecture_date}")
        finally:
            conn.close()

        return jsonify({
            "status": STATUS_PRESENT, 
            "student_number": student_number, 
            "lecture_id": lecture_id,
            "attendance_date": str(lecture_date)
        })


# ==================== 게시판 API ====================

# 파일 확장자 검증
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 작성자 정보 조회 (익명/닉네임/실명 처리)
def get_author_info(conn, author_id):
    """
    학생의 is_anonymous, nickname, name, department_name 정보를 가져와서
    표시할 이름과 학과를 반환합니다.
    """
    cur = conn.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT is_anonymous, nickname, name, department_name FROM students WHERE student_number = %s;"
    cur.execute(sql, (author_id,))
    student = cur.fetchone()
    
    if not student:
        return "알 수 없음", None
    
    # 익명 처리
    if student['is_anonymous'] == 1:
        return "익명", None
    
    # 닉네임이 있으면 닉네임 사용
    if student['nickname']:
        return student['nickname'], student['department_name']
    
    # 닉네임이 없으면 실명 사용
    return student['name'], student['department_name']

# 게시글에 좋아요를 눌렀는지 확인
def is_post_liked_by_user(conn, post_id, user_id):
    cur = conn.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT COUNT(*) as count FROM post_likes WHERE post_id = %s AND user_id = %s;"
    cur.execute(sql, (post_id, user_id))
    result = cur.fetchone()
    return result['count'] > 0

# 댓글에 좋아요를 눌렀는지 확인
def is_comment_liked_by_user(conn, comment_id, user_id):
    cur = conn.cursor(pymysql.cursors.DictCursor)
    sql = "SELECT COUNT(*) as count FROM comment_likes WHERE comment_id = %s AND user_id = %s;"
    cur.execute(sql, (comment_id, user_id))
    result = cur.fetchone()
    return result['count'] > 0

# 해시태그 추출 함수
def extract_hashtags(content):
    """
    게시글 본문에서 #태그 형식의 해시태그를 추출합니다.
    """
    hashtags = re.findall(r'#(\w+)', content)
    return list(set(hashtags))  # 중복 제거

# 이미지 URL 변환 함수
def convert_image_urls_to_full(image_urls_str):
    """
    DB에 저장된 이미지 URL 문자열을 전체 URL 리스트로 변환합니다.
    예: "uploads/posts/1/a.jpg,uploads/posts/1/b.jpg" 
        -> ["http://localhost:5000/uploads/posts/1/a.jpg", "http://localhost:5000/uploads/posts/1/b.jpg"]
    """
    if not image_urls_str:
        return []
    print(image_urls_str)
    print(f"🔍 request.host_url: '{request.host_url}'")
    print(f"🔍 원본 image_urls_str: '{image_urls_str}'")
    
    image_urls = []
    raw_urls = image_urls_str.split(',')
    for url in raw_urls:
        url = url.strip()
        if url:
            # 절대 경로인 경우 상대 경로로 추출
            if url.startswith('http://') or url.startswith('https://'):
                if 'uploads/' in url:
                    url = 'uploads/' + url.split('uploads/', 1)[1]
                    print(f"🔍 절대경로 -> 상대경로: '{url}'")
            
            # 상대 경로를 전체 URL로 변환
            base_url = request.host_url.rstrip('/')
            path = url.lstrip('/')
            full_url = f"{base_url}/{path}"
            print(f"🔍 최종 변환: '{url}' -> '{full_url}'")
            image_urls.append(full_url)
    
    print(f"✅ 최종 결과: {image_urls}")
    return image_urls

# --- 이미지 업로드 ---
@app.route('/posts/images', methods=['POST'])
def upload_post_image():
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    if 'image' not in request.files:
        return jsonify({"message": "이미지 파일이 없습니다."}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({"message": "파일이 선택되지 않았습니다."}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"message": "허용되지 않은 파일 형식입니다. (jpg, jpeg, png, gif, webp만 가능)"}), 400
    
    # 임시 폴더에 UUID 파일명으로 저장
    temp_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'temp')
    os.makedirs(temp_folder, exist_ok=True)
    
    # 원본 파일명 유지 (보안을 위해 secure_filename 사용)
    original_filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
    temp_path = os.path.join(temp_folder, unique_filename)
    
    file.save(temp_path)
    
    # 파일 크기 확인
    file_size = os.path.getsize(temp_path)
    if file_size > 10 * 1024 * 1024:
        os.remove(temp_path)
        return jsonify({"message": "파일 크기는 10MB 이하여야 합니다."}), 413
    
    # 상대 경로 반환
    relative_path = os.path.join('uploads', 'temp', unique_filename).replace('\\', '/')
    
    return jsonify({
        "url": relative_path,
        "filename": unique_filename,
        "size": file_size
    }), 200

# --- 이미지 파일 서빙 ---
@app.route('/uploads/<path:filename>', methods=['GET'])
def serve_uploaded_image(filename):
    """업로드된 이미지 파일을 제공합니다."""
    try:
        # uploads 폴더의 절대 경로
        upload_folder = os.path.abspath(app.config['UPLOAD_FOLDER'])
        return send_from_directory(upload_folder, filename)
    except FileNotFoundError:
        return jsonify({"message": "이미지를 찾을 수 없습니다."}), 404

# --- 게시글 작성 ---
@app.route('/posts', methods=['POST'])
def create_post():
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    data = request.get_json()
    board_category = data.get('category')  # 'free', 'market', 'info', 'hobby'
    title = data.get('title')
    content = data.get('content')
    image_urls = data.get('image_urls', [])  # 임시 경로 리스트
    print(image_urls)
    
    if not board_category or not title or not content:
        return jsonify({"message": "카테고리, 제목, 내용은 필수입니다."}), 400
    
    author_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # board_id 조회
        cur.execute("SELECT id FROM boards WHERE name = %s;", (board_category,))
        board = cur.fetchone()
        if not board:
            return jsonify({"message": "존재하지 않는 게시판입니다."}), 400
        
        board_id = board['id']
        
        # 해시태그 추출
        hashtags = extract_hashtags(content)
        hashtags_str = ','.join([f'#{tag}' for tag in hashtags]) if hashtags else None
        
        # 게시글 저장
        insert_sql = """
            INSERT INTO posts (board_id, author, title, content, hashtags, like_count, view_count, comment_count)
            VALUES (%s, %s, %s, %s, %s, 0, 0, 0);
        """
        cur.execute(insert_sql, (board_id, author_id, title, content, hashtags_str))
        conn.commit()
        
        post_id = cur.lastrowid
        
        # 이미지가 있으면 임시 폴더에서 실제 폴더로 이동
        final_image_urls = []
        if image_urls:
            post_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'posts', str(post_id))
            os.makedirs(post_folder, exist_ok=True)
            
            for temp_url in image_urls:
                # 절대 URL이면 상대 경로로 변환
                if temp_url.startswith('http://') or temp_url.startswith('https://'):
                    # 'uploads/' 이후 부분 추출
                    if 'uploads/' in temp_url:
                        temp_url = 'uploads/' + temp_url.split('uploads/', 1)[1]
                
                # temp_url: 'uploads/temp/uuid_filename.jpg'
                temp_path = temp_url
                if os.path.exists(temp_path):
                    filename = os.path.basename(temp_path)
                    final_path = os.path.join(post_folder, filename)
                    
                    # 파일 이동
                    os.rename(temp_path, final_path)
                    
                    # 최종 URL (상대 경로로만 저장)
                    final_url = os.path.join('uploads', 'posts', str(post_id), filename).replace('\\', '/')
                    final_image_urls.append(final_url)
            
            # DB 업데이트
            image_urls_str = ','.join(final_image_urls)
            cur.execute("UPDATE posts SET image_urls = %s WHERE id = %s;", (image_urls_str, post_id))
            conn.commit()
        
        # 작성자 정보 조회
        author_name, author_dept = get_author_info(conn, author_id)
        
        return jsonify({
            "id": post_id,
            "category": board_category,
            "title": title,
            "content": content,
            "author_id": author_id,
            "author_name": author_name,
            "author_department": author_dept,
            "created_at": datetime.now().isoformat(),
            "updated_at": None,
            "view_count": 0,
            "like_count": 0,
            "comment_count": 0,
            "image_urls": final_image_urls,
            "hashtags": hashtags,
            "is_liked_by_me": False,
            "is_mine": True
        }), 201
        
    except Exception as e:
        print(f"게시글 작성 오류: {e}")
        return jsonify({"message": "게시글 작성 중 오류가 발생했습니다."}), 500
    finally:
        conn.close()
    
# --- 내가 쓴 게시글 조회 ---
@app.route('/posts/mine', methods=['GET'])
def get_my_posts():
    """내가 작성한 게시글 목록 조회 (최적화된 버전)"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 1. 내 익명 설정 및 닉네임 먼저 조회 (한 번만)
        cur.execute("""
            SELECT is_anonymous, nickname, name, department_name
            FROM students
            WHERE student_number = %s
        """, (user_id,))
        my_info = cur.fetchone()
        
        if not my_info:
            return jsonify({"error": "사용자 정보를 찾을 수 없습니다."}), 404
        
        # 내 표시 이름 결정
        if my_info['is_anonymous'] == 1:
            my_name = "익명"
            my_dept = None
        elif my_info['nickname']:
            my_name = my_info['nickname']
            my_dept = my_info['department_name']
        else:
            my_name = my_info['name']
            my_dept = my_info['department_name']
        
        # 2. 게시글 + 좋아요 여부를 JOIN으로 한 번에 조회 (N+1 문제 해결)
        sql = """
            SELECT 
                p.*,
                b.name as board_name,
                CASE WHEN pl.id IS NOT NULL THEN 1 ELSE 0 END as is_liked
            FROM posts p
            JOIN boards b ON p.board_id = b.id
            LEFT JOIN post_likes pl ON p.id = pl.post_id AND pl.user_id = %s
            WHERE p.author = %s
            ORDER BY p.created_at DESC
        """
        cur.execute(sql, (user_id, user_id))
        posts = cur.fetchall()
        
        result = []
        for post in posts:
            # 이미지 URL 파싱 및 전체 URL 생성
            image_urls = convert_image_urls_to_full(post['image_urls'])
            
            # 해시태그 파싱
            hashtags = post['hashtags'].split(',') if post['hashtags'] else []
            hashtags = [tag.replace('#', '') for tag in hashtags]
            
            result.append({
                "id": post['id'],
                "category": post['board_name'],
                "title": post['title'],
                "content": post['content'],
                "author_id": post['author'],
                "author_name": my_name,  # 모든 게시글이 내 글이므로 동일
                "author_department": my_dept,
                "created_at": post['created_at'].isoformat() if post['created_at'] else None,
                "view_count": post['view_count'],
                "like_count": post['like_count'],
                "comment_count": post['comment_count'],
                "image_urls": image_urls,
                "hashtags": hashtags,
                "is_liked_by_me": bool(post['is_liked']),
                "is_mine": True  # 내 글이므로 항상 True
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"❌ 내 게시글 조회 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "게시글 조회 중 오류가 발생했습니다."}), 500
    finally:
        conn.close()
    
# --- 게시글 상세 조회 ---
@app.route('/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 세션에 조회 기록 저장 (사용자별 중복 방지)
        if 'viewed_posts' not in session:
            print("6. viewed_posts 키가 없음 -> 새로 생성")
            session['viewed_posts'] = []
        
        # 이 게시글을 이미 조회했는지 확인
        if post_id not in session['viewed_posts']:
            # 조회수 증가
            cur.execute("UPDATE posts SET view_count = view_count + 1 WHERE id = %s;", (post_id,))
            conn.commit()
            
            # 세션에 조회 기록 추가
            session['viewed_posts'].append(post_id)
            session.modified = True  # 세션 변경 알림
                
        # 게시글 조회
        sql = """
            SELECT p.*, b.name as board_name
            FROM posts p
            JOIN boards b ON p.board_id = b.id
            WHERE p.id = %s;
        """
        cur.execute(sql, (post_id,))
        post = cur.fetchone()
        
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404
        
        # 작성자 정보
        author_name, author_dept = get_author_info(conn, post['author'])
        
        # 좋아요 여부
        is_liked = is_post_liked_by_user(conn, post_id, user_id)
        
        # 이미지 URL 파싱 및 전체 URL 생성
        image_urls = convert_image_urls_to_full(post['image_urls'])
        
        
        # 해시태그 파싱
        hashtags = post['hashtags'].split(',') if post['hashtags'] else []
        hashtags = [tag.replace('#', '') for tag in hashtags]
        
        return jsonify({
            "id": post['id'],
            "category": post['board_name'],
            "title": post['title'],
            "content": post['content'],
            "author_id": post['author'],
            "author_name": author_name,
            "author_department": author_dept,
            "created_at": post['created_at'].isoformat() if post['created_at'] else None,
            "updated_at": None,
            "view_count": post['view_count'],
            "like_count": post['like_count'],
            "comment_count": post['comment_count'],
            "image_urls": image_urls,
            "hashtags": hashtags,
            "is_liked_by_me": is_liked,
            "is_mine": post['author'] == user_id
        }), 200
        
    finally:
        conn.close()

# --- 게시글 수정 ---
@app.route('/posts/<int:post_id>', methods=['PUT'])
def update_post(post_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    data = request.get_json()
    
    try:
        conn, cur = conn_cur_create()
        
        # 게시글 소유자 확인
        cur.execute("SELECT author FROM posts WHERE id = %s;", (post_id,))
        post = cur.fetchone()
        
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404
        
        if post['author'] != user_id:
            return jsonify({"message": "본인이 작성한 게시글만 수정할 수 있습니다."}), 403
        
        # 수정할 필드
        title = data.get('title')
        content = data.get('content')
        image_urls = data.get('image_urls', [])
        
        if not title or not content:
            return jsonify({"message": "제목과 내용은 필수입니다."}), 400
        
        # 해시태그 추출
        hashtags = extract_hashtags(content)
        hashtags_str = ','.join([f'#{tag}' for tag in hashtags]) if hashtags else None
        
        # 이미지 처리
        final_image_urls = []
        if image_urls:
            post_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'posts', str(post_id))
            os.makedirs(post_folder, exist_ok=True)
            
            for temp_url in image_urls:
                # 절대 URL이면 상대 경로로 변환
                if temp_url.startswith('http://') or temp_url.startswith('https://'):
                    if 'uploads/' in temp_url:
                        temp_url = 'uploads/' + temp_url.split('uploads/', 1)[1]
                
                if 'temp' in temp_url and os.path.exists(temp_url):
                    filename = os.path.basename(temp_url)
                    final_path = os.path.join(post_folder, filename)
                    os.rename(temp_url, final_path)
                    final_url = os.path.join('uploads', 'posts', str(post_id), filename).replace('\\', '/')
                    final_image_urls.append(final_url)
                else:
                    # 기존 이미지 유지 (상대 경로로만 저장)
                    final_image_urls.append(temp_url)
        
        image_urls_str = ','.join(final_image_urls) if final_image_urls else None
        
        # DB 업데이트
        update_sql = """
            UPDATE posts 
            SET title = %s, content = %s, hashtags = %s, image_urls = %s
            WHERE id = %s;
        """
        cur.execute(update_sql, (title, content, hashtags_str, image_urls_str, post_id))
        conn.commit()
        
        return jsonify({"message": "게시글이 수정되었습니다."}), 200
        
    finally:
        conn.close()

# --- 게시글 삭제 ---
@app.route('/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 게시글 소유자 확인
        cur.execute("SELECT author, image_urls FROM posts WHERE id = %s;", (post_id,))
        post = cur.fetchone()
        
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404
        
        if post['author'] != user_id:
            return jsonify({"message": "본인이 작성한 게시글만 삭제할 수 있습니다."}), 403
        
        # 이미지 파일 삭제
        if post['image_urls']:
            for img_url in post['image_urls'].split(','):
                if os.path.exists(img_url):
                    os.remove(img_url)
        
        # 게시글 삭제
        cur.execute("DELETE FROM posts WHERE id = %s;", (post_id,))
        conn.commit()
        
        return jsonify({"message": "게시글이 삭제되었습니다."}), 200
        
    finally:
        conn.close()

# --- 인기글 목록 조회 ---
@app.route('/boards/popular', methods=['GET'])
def get_popular_posts():
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error

    user_id = payload['username']
    cursor = request.args.get('cursor', type=int)  # 마지막 게시글 ID
    limit = request.args.get('limit', 20, type=int)

    try:
        conn, cur = conn_cur_create()

        # JOIN을 사용한 단일 쿼리로 최적화 (N+1 문제 해결)
        # 좋아요 10개 이상인 게시글만 조회, 최신순 정렬
        if cursor:
            sql = """
                SELECT
                    p.*,
                    b.name as board_name,
                    s.is_anonymous,
                    s.nickname,
                    s.name as student_name,
                    s.department_name,
                    CASE WHEN pl.id IS NOT NULL THEN 1 ELSE 0 END as is_liked
                FROM posts p
                JOIN boards b ON p.board_id = b.id
                JOIN students s ON p.author = s.student_number
                LEFT JOIN post_likes pl ON p.id = pl.post_id AND pl.user_id = %s
                WHERE p.like_count >= 10 AND p.id < %s
                ORDER BY p.id DESC
                LIMIT %s
            """
            cur.execute(sql, (user_id, cursor, limit))
        else:
            sql = """
                SELECT
                    p.*,
                    b.name as board_name,
                    s.is_anonymous,
                    s.nickname,
                    s.name as student_name,
                    s.department_name,
                    CASE WHEN pl.id IS NOT NULL THEN 1 ELSE 0 END as is_liked
                FROM posts p
                JOIN boards b ON p.board_id = b.id
                JOIN students s ON p.author = s.student_number
                LEFT JOIN post_likes pl ON p.id = pl.post_id AND pl.user_id = %s
                WHERE p.like_count >= 10
                ORDER BY p.id DESC
                LIMIT %s
            """
            cur.execute(sql, (user_id, limit))

        posts = cur.fetchall()

        result = []
        next_cursor = None

        for post in posts:
            # 익명 여부에 따라 작성자 정보 결정
            if post['is_anonymous'] == 1:
                author_name = "익명"
                author_dept = None
            elif post['nickname']:
                author_name = post['nickname']
                author_dept = post['department_name']
            else:
                author_name = post['student_name']
                author_dept = post['department_name']

            image_urls = convert_image_urls_to_full(post['image_urls'])
            hashtags = post['hashtags'].split(',') if post['hashtags'] else []
            hashtags = [tag.replace('#', '') for tag in hashtags]

            result.append({
                "id": post['id'],
                "category": post['board_name'],
                "title": post['title'],
                "content": post['content'][:100] + '...' if len(post['content']) > 100 else post['content'],
                "author_id": post['author'],
                "author_name": author_name,
                "author_department": author_dept,
                "created_at": post['created_at'].isoformat() if post['created_at'] else None,
                "view_count": post['view_count'],
                "like_count": post['like_count'],
                "comment_count": post['comment_count'],
                "image_urls": image_urls,
                "hashtags": hashtags,
                "is_liked_by_me": bool(post['is_liked']),
                "is_mine": post['author'] == user_id
            })

            next_cursor = post['id']

        # 클라이언트가 List를 기대하므로 배열만 반환
        return jsonify(result), 200
        
    finally:
        conn.close()

# --- 카테고리별 게시글 목록 (커서 기반 페이지네이션) ---
@app.route('/boards/<string:category>/posts', methods=['GET'])
def get_posts_by_category(category):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error

    user_id = payload['username']
    cursor = request.args.get('cursor', type=int)  # 마지막 게시글 ID
    limit = request.args.get('limit', 20, type=int)
    sort = request.args.get('sort', 'latest')  # 정렬 기준: latest, views, comments, likes
    
    try:
        conn, cur = conn_cur_create()

        # board_id 조회
        cur.execute("SELECT id FROM boards WHERE name = %s;", (category,))
        board = cur.fetchone()
        if not board:
            return jsonify({"message": "존재하지 않는 게시판입니다."}), 400

        board_id = board['id']

        # 정렬 기준 결정
        if sort == 'views':
            order_by = "p.view_count DESC, p.id DESC"
        elif sort == 'comments':
            order_by = "p.comment_count DESC, p.id DESC"
        elif sort == 'likes':
            order_by = "p.like_count DESC, p.id DESC"
        else:  # latest (기본값)
            order_by = "p.id DESC"

        # JOIN을 사용한 단일 쿼리로 최적화 (N+1 문제 해결)
        if cursor:
            sql = f"""
                SELECT
                    p.*,
                    b.name as board_name,
                    s.is_anonymous,
                    s.nickname,
                    s.name as student_name,
                    s.department_name,
                    CASE WHEN pl.id IS NOT NULL THEN 1 ELSE 0 END as is_liked
                FROM posts p
                JOIN boards b ON p.board_id = b.id
                JOIN students s ON p.author = s.student_number
                LEFT JOIN post_likes pl ON p.id = pl.post_id AND pl.user_id = %s
                WHERE p.board_id = %s AND p.id < %s
                ORDER BY {order_by}
                LIMIT %s
            """
            cur.execute(sql, (user_id, board_id, cursor, limit))
        else:
            sql = f"""
                SELECT
                    p.*,
                    b.name as board_name,
                    s.is_anonymous,
                    s.nickname,
                    s.name as student_name,
                    s.department_name,
                    CASE WHEN pl.id IS NOT NULL THEN 1 ELSE 0 END as is_liked
                FROM posts p
                JOIN boards b ON p.board_id = b.id
                JOIN students s ON p.author = s.student_number
                LEFT JOIN post_likes pl ON p.id = pl.post_id AND pl.user_id = %s
                WHERE p.board_id = %s
                ORDER BY {order_by}
                LIMIT %s
            """
            cur.execute(sql, (user_id, board_id, limit))
        
        posts = cur.fetchall()
        
        result = []
        next_cursor = None
        
        for post in posts:
            # 익명 여부에 따라 작성자 정보 결정
            if post['is_anonymous'] == 1:
                author_name = "익명"
                author_dept = None
            elif post['nickname']:
                author_name = post['nickname']
                author_dept = post['department_name']
            else:
                author_name = post['student_name']
                author_dept = post['department_name']
            
            image_urls = convert_image_urls_to_full(post['image_urls'])
            hashtags = post['hashtags'].split(',') if post['hashtags'] else []
            hashtags = [tag.replace('#', '') for tag in hashtags]
            
            result.append({
                "id": post['id'],
                "category": post['board_name'],
                "title": post['title'],
                "content": post['content'][:100] + '...' if len(post['content']) > 100 else post['content'],
                "author_id": post['author'],
                "author_name": author_name,
                "author_department": author_dept,
                "created_at": post['created_at'].isoformat() if post['created_at'] else None,
                "view_count": post['view_count'],
                "like_count": post['like_count'],
                "comment_count": post['comment_count'],
                "image_urls": image_urls,
                "hashtags": hashtags,
                "is_liked_by_me": bool(post['is_liked']),
                "is_mine": post['author'] == user_id
            })
            
            next_cursor = post['id']
        
        # 클라이언트가 List를 기대하므로 배열만 반환
        return jsonify(result), 200
        
    finally:
        conn.close()

# --- 게시글 좋아요 토글 ---
@app.route('/posts/<int:post_id>/like', methods=['POST'])
def toggle_post_like(post_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 좋아요 여부 확인
        cur.execute("SELECT id FROM post_likes WHERE post_id = %s AND user_id = %s;", (post_id, user_id))
        like = cur.fetchone()
        
        if like:
            # 좋아요 취소
            cur.execute("DELETE FROM post_likes WHERE post_id = %s AND user_id = %s;", (post_id, user_id))
            cur.execute("UPDATE posts SET like_count = like_count - 1 WHERE id = %s;", (post_id,))
            conn.commit()
            
            # 업데이트된 좋아요 수 조회
            cur.execute("SELECT like_count FROM posts WHERE id = %s;", (post_id,))
            post = cur.fetchone()
            
            return jsonify({
                "is_liked": False,
                "like_count": post['like_count']
            }), 200
        else:
            # 좋아요 추가
            cur.execute("INSERT INTO post_likes (post_id, user_id) VALUES (%s, %s);", (post_id, user_id))
            cur.execute("UPDATE posts SET like_count = like_count + 1 WHERE id = %s;", (post_id,))
            conn.commit()
            
            # 업데이트된 좋아요 수 조회
            cur.execute("SELECT like_count FROM posts WHERE id = %s;", (post_id,))
            post = cur.fetchone()
            
            return jsonify({
                "is_liked": True,
                "like_count": post['like_count']
            }), 200
        
    finally:
        conn.close()

# --- 댓글 목록 조회 ---
@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def get_comments(post_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 모든 댓글 조회 (부모 댓글만) - students 테이블 조인하여 익명 설정 확인
        sql = """
            SELECT c.*, COALESCE(s.is_anonymous, 0) as is_anonymous
            FROM comments c
            LEFT JOIN students s ON c.author = s.student_number
            WHERE c.post_id = %s AND c.parent_id IS NULL
            ORDER BY c.created_at ASC;
        """
        cur.execute(sql, (post_id,))
        comments = cur.fetchall()
        print(f"📝 댓글 조회 - post_id: {post_id}, 조회된 댓글 수: {len(comments)}")
        
        result = []
        for comment in comments:
            # 익명 번호 처리 (students 테이블의 is_anonymous 확인)
            is_anonymous = comment['is_anonymous'] == 1
            if is_anonymous and comment.get('anonymous_number'):
                author_name = f"익명{comment['anonymous_number']}"
                author_dept = None
            else:
                author_name, author_dept = get_author_info(conn, comment['author'])
            
            is_liked = is_comment_liked_by_user(conn, comment['id'], user_id)
            
            # 모든 대댓글 조회 (재귀적으로 모든 하위 댓글 가져오기)
            # WITH RECURSIVE로 parent_id가 이 댓글을 참조하는 모든 댓글 조회
            cur.execute("""
                WITH RECURSIVE comment_tree AS (
                    -- 직접 자식 댓글
                    SELECT c.*, COALESCE(s.is_anonymous, 0) as is_anonymous, c.id as original_id
                    FROM comments c
                    LEFT JOIN students s ON c.author = s.student_number
                    WHERE c.parent_id = %s
                    
                    UNION ALL
                    
                    -- 자식의 자식 댓글 (재귀)
                    SELECT c.*, COALESCE(s.is_anonymous, 0) as is_anonymous, c.id as original_id
                    FROM comments c
                    LEFT JOIN students s ON c.author = s.student_number
                    INNER JOIN comment_tree ct ON c.parent_id = ct.original_id
                )
                SELECT * FROM comment_tree
                ORDER BY created_at ASC;
            """, (comment['id'],))
            replies = cur.fetchall()
            
            reply_list = []
            for reply in replies:
                # 대댓글 익명 번호 처리 (students 테이블의 is_anonymous 확인)
                reply_is_anonymous = reply['is_anonymous'] == 1
                if reply_is_anonymous and reply.get('anonymous_number'):
                    reply_author_name = f"익명{reply['anonymous_number']}"
                    reply_author_dept = None
                else:
                    reply_author_name, reply_author_dept = get_author_info(conn, reply['author'])
                
                reply_is_liked = is_comment_liked_by_user(conn, reply['id'], user_id)
                
                reply_list.append({
                    "id": reply['id'],
                    "post_id": reply['post_id'],
                    "parent_comment_id": reply['parent_id'],
                    "author_id": reply['author'],  # 익명이어도 실제 author_id 반환
                    "author_name": reply_author_name,
                    "author_department": reply_author_dept,
                    "content": "삭제된 댓글입니다." if reply['is_deleted'] == 1 else reply['content'],
                    "created_at": reply['created_at'].isoformat() if reply['created_at'] else None,
                    "updated_at": reply['update_at'].isoformat() if reply['update_at'] else None,
                    "like_count": reply['up_count'],
                    "is_deleted": reply['is_deleted'] == 1,
                    "is_liked_by_me": reply_is_liked,
                    "is_mine": reply['author'] == user_id,
                    "is_anonymous": reply_is_anonymous,
                    "anonymous_number": reply.get('anonymous_number'),
                    "replies": []
                })
            
            result.append({
                "id": comment['id'],
                "post_id": comment['post_id'],
                "parent_comment_id": None,
                "author_id": comment['author'],  # 익명이어도 실제 author_id 반환
                "author_name": author_name,
                "author_department": author_dept,
                "content": "삭제된 댓글입니다." if comment['is_deleted'] == 1 else comment['content'],
                "created_at": comment['created_at'].isoformat() if comment['created_at'] else None,
                "updated_at": comment['update_at'].isoformat() if comment['update_at'] else None,
                "like_count": comment['up_count'],
                "is_deleted": comment['is_deleted'] == 1,
                "is_liked_by_me": is_liked,
                "is_mine": comment['author'] == user_id,
                "is_anonymous": is_anonymous,
                "anonymous_number": comment.get('anonymous_number'),
                "replies": reply_list
            })
        
        print(result)
        return jsonify(result), 200
        
    finally:
        conn.close()

# --- 댓글 작성 ---
@app.route('/posts/<int:post_id>/comments', methods=['POST'])
def create_comment(post_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    data = request.get_json()
    content = data.get('content')
    parent_comment_id = data.get('parent_comment_id')
    
    # parent_comment_id 정규화: None, 0, 빈 문자열 -> None으로 통일
    if not parent_comment_id or parent_comment_id == 0 or parent_comment_id == "":
        parent_comment_id = None
    
    print(f"💬 댓글 작성 - post_id: {post_id}, parent_id: {parent_comment_id}, content: {content[:30]}...")
    
    if not content:
        return jsonify({"message": "댓글 내용은 필수입니다."}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        # 학생의 익명 설정 확인
        cur.execute("SELECT is_anonymous FROM students WHERE student_number = %s;", (user_id,))
        student = cur.fetchone()
        is_anonymous = student['is_anonymous'] == 1 if student else False
        
        # 익명 번호 처리
        anonymous_number = None
        if is_anonymous:
            # 해당 게시글에서 이 사용자의 기존 익명 번호 조회
            cur.execute("""
                SELECT anonymous_number 
                FROM comments 
                WHERE post_id = %s AND author = %s AND anonymous_number IS NOT NULL 
                LIMIT 1;
            """, (post_id, user_id))
            existing = cur.fetchone()
            
            if existing and existing['anonymous_number']:
                # 기존 번호 재사용
                anonymous_number = existing['anonymous_number']
            else:
                # 새 번호 할당 (해당 게시글의 최대값 + 1)
                cur.execute("""
                    SELECT COALESCE(MAX(anonymous_number), 0) as max_num 
                    FROM comments 
                    WHERE post_id = %s AND anonymous_number IS NOT NULL;
                """, (post_id,))
                max_result = cur.fetchone()
                anonymous_number = int(max_result['max_num']) + 1
        
        # 댓글 저장
        sql = """
            INSERT INTO comments (post_id, parent_id, author, content, up_count, is_deleted, anonymous_number)
            VALUES (%s, %s, %s, %s, 0, 0, %s);
        """
        cur.execute(sql, (post_id, parent_comment_id, user_id, content, anonymous_number))
        
        print(f"✅ 댓글 저장 완료 - post_id: {post_id}, parent_id: {parent_comment_id}, author: {user_id}")
        
        # 게시글의 댓글 수 증가
        cur.execute("UPDATE posts SET comment_count = comment_count + 1 WHERE id = %s;", (post_id,))
        conn.commit()
        
        comment_id = cur.lastrowid
        
        # 작성자 정보 (익명 처리)
        if is_anonymous and anonymous_number:
            author_name = f"익명{anonymous_number}"
            author_dept = None
        else:
            author_name, author_dept = get_author_info(conn, user_id)
        
        # ========== FCM 푸시 알림 발송 ==========
        try:
            if parent_comment_id:
                # 대댓글: 부모 댓글 작성자에게 알림
                cur.execute("""
                    SELECT c.author, p.title, p.board_id
                    FROM comments c
                    JOIN posts p ON c.post_id = p.id
                    WHERE c.id = %s
                """, (parent_comment_id,))
                parent_info = cur.fetchone()
                
                if parent_info and parent_info['author'] != user_id:
                    # 자신의 댓글에 답글 단 경우는 제외
                    fcm_manager.send_comment_reply_notification(
                        comment_author_id=parent_info['author'],
                        replier_name=author_name,
                        post_title=parent_info['title'],
                        post_id=post_id,
                        parent_comment_id=parent_comment_id,
                        reply_id=comment_id,
                        category_id=parent_info['board_id']  # board_id를 category_id로 전달
                    )
            else:
                # 일반 댓글: 게시글 작성자에게 알림
                cur.execute("SELECT author, title, board_id FROM posts WHERE id = %s", (post_id,))
                post_info = cur.fetchone()
                
                if post_info and post_info['author'] != user_id:
                    # 자신의 게시글에 댓글 단 경우는 제외
                    fcm_manager.send_post_comment_notification(
                        post_author_id=post_info['author'],
                        commenter_name=author_name,
                        post_title=post_info['title'],
                        post_id=post_id,
                        comment_id=comment_id,
                        category_id=post_info['board_id']  # board_id를 category_id로 전달
                    )
        except Exception as fcm_error:
            # FCM 알림 실패해도 댓글 작성은 성공 처리
            print(f"⚠️ FCM 알림 발송 실패 (댓글 작성은 성공): {fcm_error}")
        
        return jsonify({
            "id": comment_id,
            "post_id": post_id,
            "parent_comment_id": parent_comment_id,
            "author_id": user_id if not is_anonymous else None,
            "author_name": author_name,
            "author_department": author_dept,
            "content": content,
            "created_at": datetime.now().isoformat(),
            "updated_at": None,
            "like_count": 0,
            "is_deleted": False,
            "is_liked_by_me": False,
            "is_mine": True,
            "is_anonymous": is_anonymous,
            "anonymous_number": anonymous_number,
            "replies": []
        }), 201
        
    finally:
        conn.close()

# --- 댓글 수정 ---
@app.route('/comments/<int:comment_id>', methods=['PUT'])
def update_comment(comment_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    data = request.get_json()
    content = data.get('content')
    
    if not content:
        return jsonify({"message": "댓글 내용은 필수입니다."}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        # 댓글 소유자 확인
        cur.execute("SELECT author, post_id, is_deleted FROM comments WHERE id = %s;", (comment_id,))
        comment = cur.fetchone()
        
        if not comment:
            return jsonify({"message": "댓글을 찾을 수 없습니다."}), 404
        
        if comment['author'] != user_id:
            return jsonify({"message": "본인이 작성한 댓글만 수정할 수 있습니다."}), 403
        
        if comment['is_deleted'] == 1:
            return jsonify({"message": "삭제된 댓글은 수정할 수 없습니다."}), 400
        
        # 댓글 수정
        cur.execute("""
            UPDATE comments 
            SET content = %s, update_at = NOW()
            WHERE id = %s;
        """, (content, comment_id))
        conn.commit()
        
        # 수정된 댓글 정보 조회
        cur.execute("SELECT * FROM comments WHERE id = %s;", (comment_id,))
        updated_comment = cur.fetchone()
        
        # 작성자 정보
        author_name, author_dept = get_author_info(conn, user_id)
        
        return jsonify({
            "id": updated_comment['id'],
            "post_id": updated_comment['post_id'],
            "parent_comment_id": updated_comment['parent_id'],
            "author_id": updated_comment['author'],
            "author_name": author_name,
            "author_department": author_dept,
            "content": updated_comment['content'],
            "created_at": updated_comment['created_at'].isoformat() if updated_comment['created_at'] else None,
            "updated_at": updated_comment['update_at'].isoformat() if updated_comment['update_at'] else None,
            "like_count": updated_comment['up_count'],
            "is_deleted": False,
            "is_liked_by_me": is_comment_liked_by_user(conn, comment_id, user_id),
            "is_mine": True,
            "replies": []
        }), 200
        
    finally:
        conn.close()

# --- 댓글 삭제 ---
@app.route('/comments/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 댓글 소유자 및 부모 댓글 정보 확인
        cur.execute("SELECT author, post_id, parent_id FROM comments WHERE id = %s;", (comment_id,))
        comment = cur.fetchone()
        
        if not comment:
            return jsonify({"message": "댓글을 찾을 수 없습니다."}), 404
        
        if comment['author'] != user_id:
            return jsonify({"message": "본인이 작성한 댓글만 삭제할 수 있습니다."}), 403
        
        parent_id = comment['parent_id']
        post_id = comment['post_id']
        
        # 대댓글 존재 여부 확인 (본인이 부모 댓글인 경우)
        cur.execute("SELECT COUNT(*) as count FROM comments WHERE parent_id = %s;", (comment_id,))
        result = cur.fetchone()
        has_replies = result['count'] > 0
        
        if has_replies:
            # 소프트 삭제 (내용만 변경)
            cur.execute("""
                UPDATE comments 
                SET content = '삭제된 댓글입니다.', is_deleted = 1 
                WHERE id = %s;
            """, (comment_id,))
            conn.commit()
            
            return jsonify({
                "message": "댓글이 삭제되었습니다.",
                "is_soft_deleted": True
            }), 200
        else:
            # 완전 삭제
            cur.execute("DELETE FROM comments WHERE id = %s;", (comment_id,))
            
            # 게시글의 댓글 수 감소
            cur.execute("UPDATE posts SET comment_count = comment_count - 1 WHERE id = %s;", (post_id,))
            
            # 대댓글인 경우, 부모 댓글 확인
            if parent_id:
                # 부모 댓글의 남은 자식 개수 확인
                cur.execute("SELECT COUNT(*) as count FROM comments WHERE parent_id = %s;", (parent_id,))
                siblings_result = cur.fetchone()
                siblings_count = siblings_result['count']
                
                # 부모 댓글 정보 확인
                cur.execute("SELECT is_deleted FROM comments WHERE id = %s;", (parent_id,))
                parent = cur.fetchone()
                
                # 자식이 1개 이하이고 부모가 소프트 삭제된 상태라면 부모도 완전 삭제
                if parent and siblings_count <= 1 and parent['is_deleted'] == 1:
                    cur.execute("DELETE FROM comments WHERE id = %s;", (parent_id,))
                    # 부모 댓글도 삭제했으므로 게시글의 댓글 수 추가 감소
                    cur.execute("UPDATE posts SET comment_count = comment_count - 1 WHERE id = %s;", (post_id,))
            
            conn.commit()
            
            return jsonify({
                "message": "댓글이 삭제되었습니다.",
                "is_soft_deleted": False
            }), 200
        
    finally:
        conn.close()

# --- 댓글 좋아요 토글 ---
@app.route('/comments/<int:comment_id>/like', methods=['POST'])
def toggle_comment_like(comment_id):
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 좋아요 여부 확인
        cur.execute("SELECT id FROM comment_likes WHERE comment_id = %s AND user_id = %s;", (comment_id, user_id))
        like = cur.fetchone()
        
        if like:
            # 좋아요 취소
            cur.execute("DELETE FROM comment_likes WHERE comment_id = %s AND user_id = %s;", (comment_id, user_id))
            cur.execute("UPDATE comments SET up_count = up_count - 1 WHERE id = %s;", (comment_id,))
            conn.commit()
            
            cur.execute("SELECT up_count FROM comments WHERE id = %s;", (comment_id,))
            comment = cur.fetchone()
            
            return jsonify({
                "is_liked": False,
                "like_count": comment['up_count']
            }), 200
        else:
            # 좋아요 추가
            cur.execute("INSERT INTO comment_likes (comment_id, user_id) VALUES (%s, %s);", (comment_id, user_id))
            cur.execute("UPDATE comments SET up_count = up_count + 1 WHERE id = %s;", (comment_id,))
            conn.commit()
            
            cur.execute("SELECT up_count FROM comments WHERE id = %s;", (comment_id,))
            comment = cur.fetchone()
            
            return jsonify({
                "is_liked": True,
                "like_count": comment['up_count']
            }), 200
        
    finally:
        conn.close()

# --- 통합 검색 ---
@app.route('/search', methods=['GET'])
def search_posts():
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    query = request.args.get('q', '').strip()
    category = request.args.get('category')
    cursor = request.args.get('cursor', type=int)
    limit = request.args.get('limit', 20, type=int)
    
    if not query or len(query) < 2:
        return jsonify({"message": "검색어는 최소 2자 이상이어야 합니다."}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        # 검색 쿼리 (제목, 내용, 해시태그)
        search_pattern = f"%{query}%"
        
        if category:
            # 특정 카테고리 검색
            cur.execute("SELECT id FROM boards WHERE name = %s;", (category,))
            board = cur.fetchone()
            if not board:
                return jsonify({"message": "존재하지 않는 게시판입니다."}), 400
            board_id = board['id']
            
            if cursor:
                sql = """
                    SELECT p.*, b.name as board_name
                    FROM posts p
                    JOIN boards b ON p.board_id = b.id
                    WHERE p.board_id = %s AND p.id < %s
                    AND (p.title LIKE %s OR p.content LIKE %s OR p.hashtags LIKE %s)
                    ORDER BY p.id DESC
                    LIMIT %s;
                """
                cur.execute(sql, (board_id, cursor, search_pattern, search_pattern, search_pattern, limit))
            else:
                sql = """
                    SELECT p.*, b.name as board_name
                    FROM posts p
                    JOIN boards b ON p.board_id = b.id
                    WHERE p.board_id = %s
                    AND (p.title LIKE %s OR p.content LIKE %s OR p.hashtags LIKE %s)
                    ORDER BY p.id DESC
                    LIMIT %s;
                """
                cur.execute(sql, (board_id, search_pattern, search_pattern, search_pattern, limit))
        else:
            # 전체 게시판 검색
            if cursor:
                sql = """
                    SELECT p.*, b.name as board_name
                    FROM posts p
                    JOIN boards b ON p.board_id = b.id
                    WHERE p.id < %s
                    AND (p.title LIKE %s OR p.content LIKE %s OR p.hashtags LIKE %s)
                    ORDER BY p.id DESC
                    LIMIT %s;
                """
                cur.execute(sql, (cursor, search_pattern, search_pattern, search_pattern, limit))
            else:
                sql = """
                    SELECT p.*, b.name as board_name
                    FROM posts p
                    JOIN boards b ON p.board_id = b.id
                    WHERE p.title LIKE %s OR p.content LIKE %s OR p.hashtags LIKE %s
                    ORDER BY p.id DESC
                    LIMIT %s;
                """
                cur.execute(sql, (search_pattern, search_pattern, search_pattern, limit))
        
        posts = cur.fetchall()
        
        result = []
        next_cursor = None
        
        for post in posts:
            author_name, author_dept = get_author_info(conn, post['author'])
            is_liked = is_post_liked_by_user(conn, post['id'], user_id)
            
            image_urls = convert_image_urls_to_full(post['image_urls'])
            hashtags = post['hashtags'].split(',') if post['hashtags'] else []
            hashtags = [tag.replace('#', '') for tag in hashtags]
            
            result.append({
                "id": post['id'],
                "category": post['board_name'],
                "title": post['title'],
                "content": post['content'][:100] + '...' if len(post['content']) > 100 else post['content'],
                "author_id": post['author'],
                "author_name": author_name,
                "author_department": author_dept,
                "created_at": post['created_at'].isoformat() if post['created_at'] else None,
                "view_count": post['view_count'],
                "like_count": post['like_count'],
                "comment_count": post['comment_count'],
                "image_urls": image_urls,
                "hashtags": hashtags,
                "is_liked_by_me": is_liked,
                "is_mine": post['author'] == user_id
            })
            
            next_cursor = post['id']
        
        # 클라이언트가 List를 기대하므로 배열만 반환
        return jsonify(result), 200
        
    finally:
        conn.close()


# ==================== 채팅 REST API ====================

@app.route('/chat/rooms', methods=['GET'])
def get_chat_rooms():
    """채팅방 목록 조회"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 내 채팅방 목록 조회 (최신순)
        sql = """
        SELECT 
            cr.id,
            cr.room_name AS title,
            cr.post_id,
            cr.comment_id,
            cr.updated_at,
            IF(cr.user1_id = %s, cr.user2_id, cr.user1_id) AS partner_id,
            IF(cr.user1_id = %s, cr.user2_left, cr.user1_left) AS is_partner_left,
            (SELECT content FROM chat_messages WHERE room_id = cr.id ORDER BY sent_at DESC LIMIT 1) AS last_message,
            (SELECT sent_at FROM chat_messages WHERE room_id = cr.id ORDER BY sent_at DESC LIMIT 1) AS last_message_time,
            (SELECT COUNT(*) FROM chat_messages WHERE room_id = cr.id AND sender_id != %s AND is_read = 0) AS unread_count
        FROM chat_rooms cr
        WHERE (cr.user1_id = %s OR cr.user2_id = %s)
          AND NOT (cr.user1_id = %s AND cr.user1_left = 1)
          AND NOT (cr.user2_id = %s AND cr.user2_left = 1)
        ORDER BY cr.updated_at DESC;
        """
        cur.execute(sql, (user_id, user_id, user_id, user_id, user_id, user_id, user_id))
        rooms = cur.fetchall()
        
        # 상대방 정보 조회
        result = []
        for room in rooms:
            partner_id = room['partner_id']
            
            # 상대방 정보 가져오기
            cur.execute("""
                SELECT name, nickname, is_anonymous, department_name 
                FROM students 
                WHERE student_number = %s
            """, (partner_id,))
            partner = cur.fetchone()
            
            if partner:
                # 익명 여부에 따라 이름 설정
                partner_name = "익명" if partner['is_anonymous'] else (partner['nickname'] or partner['name'])
                
                result.append({
                    "id": room['id'],
                    "title": room['title'],
                    "post_id": room['post_id'],
                    "comment_id": room['comment_id'],
                    "partner_id": partner_id,
                    "partner_name": partner_name,
                    "partner_is_anonymous": bool(partner['is_anonymous']),
                    "last_message": room['last_message'] or "",
                    "last_message_time": room['last_message_time'].isoformat() if room['last_message_time'] else None,
                    "has_unread": room['unread_count'] > 0,
                    "is_partner_left": bool(room['is_partner_left']),
                    "updated_at": room['updated_at'].isoformat()
                })
        
        return jsonify({"rooms": result})
        
    except Exception as e:
        print(f"채팅방 목록 조회 에러: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/chat/rooms', methods=['POST'])
def create_chat_room():
    """채팅방 생성"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    data = request.get_json()
    
    partner_id = data.get('partner_id')
    post_id = data.get('post_id')
    comment_id = data.get('comment_id')  # 선택적
    
    # comment_id 유효성 확인: 빈 값이나 0이면 None으로 처리
    if comment_id is not None and (comment_id == 0 or comment_id == '' or comment_id == '0'):
        comment_id = None
    
    if not partner_id or not post_id:
        return jsonify({"error": "Invalid request", "message": "partner_id and post_id are required"}), 400
    
    # 자기 자신에게 쪽지 방지
    if user_id == partner_id:
        return jsonify({"error": "Invalid request", "message": "Cannot send message to yourself"}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        print(f"📝 채팅방 생성 요청: user={user_id}, partner={partner_id}, post={post_id}, comment={comment_id}")
        
        # 상대방 존재 여부 확인
        cur.execute("SELECT student_number FROM students WHERE student_number = %s", (partner_id,))
        partner_exists = cur.fetchone()
        if not partner_exists:
            print(f"❌ 상대방을 찾을 수 없음: {partner_id}")
            return jsonify({"error": "Not found", "message": "Partner not found"}), 404
        
        # 게시글 제목 조회
        cur.execute("SELECT title FROM posts WHERE id = %s", (post_id,))
        post = cur.fetchone()
        
        if not post:
            print(f"❌ 게시글을 찾을 수 없음: post_id={post_id}")
            return jsonify({"error": "Not found", "message": "Post not found"}), 404
        
        # 채팅방 제목 생성
        title = post['title'] if not comment_id else f"{post['title']}의 댓글"
        
        # comment_id가 제공된 경우, 해당 댓글이 실제로 존재하는지 확인
        if comment_id:
            cur.execute("SELECT id FROM comments WHERE id = %s", (comment_id,))
            comment_exists = cur.fetchone()
            print(f"🔍 댓글 존재 확인: comment_id={comment_id}, exists={comment_exists}")
            if not comment_exists:
                print(f"⚠️ 댓글을 찾을 수 없음 (삭제됨?): comment_id={comment_id} - 채팅방은 생성함")
                # 댓글이 삭제되었어도 채팅방은 생성 가능하도록 comment_id를 NULL로 처리
                comment_id = None
        
        # 기존 채팅방 확인
        user1 = min(user_id, partner_id)
        user2 = max(user_id, partner_id)
        
        sql = """
        SELECT id, room_name, created_at,
               user1_left, user2_left
        FROM chat_rooms
        WHERE user1_id = %s AND user2_id = %s 
          AND post_id = %s 
          AND (comment_id <=> %s)
        """
        cur.execute(sql, (user1, user2, post_id, comment_id))
        existing_room = cur.fetchone()
        
        if existing_room:
            # 나간 상태라면 재입장 불가
            if (user_id == user1 and existing_room['user1_left']) or \
               (user_id == user2 and existing_room['user2_left']):
                return jsonify({"error": "Forbidden", "message": "Cannot rejoin a left chat room"}), 403
            
            # 상대방 정보 조회
            cur.execute("""
                SELECT name, nickname, is_anonymous 
                FROM students 
                WHERE student_number = %s
            """, (partner_id,))
            partner = cur.fetchone()
            partner_name = "익명" if partner['is_anonymous'] else (partner['nickname'] or partner['name'])
            
            return jsonify({
                "room_id": existing_room['id'],
                "title": existing_room['room_name'],
                "partner_id": partner_id,
                "partner_name": partner_name,
                "created_at": existing_room['created_at'].isoformat()
            }), 200
        
        # 새 채팅방 생성
        sql = """
        INSERT INTO chat_rooms (room_name, post_id, comment_id, user1_id, user2_id)
        VALUES (%s, %s, %s, %s, %s)
        """
        cur.execute(sql, (title, post_id, comment_id, user1, user2))
        conn.commit()
        room_id = cur.lastrowid
        
        # 상대방 정보 조회
        cur.execute("""
            SELECT name, nickname, is_anonymous 
            FROM students 
            WHERE student_number = %s
        """, (partner_id,))
        partner = cur.fetchone()
        partner_name = "익명" if partner['is_anonymous'] else (partner['nickname'] or partner['name'])
        
        return jsonify({
            "room_id": room_id,
            "title": title,
            "partner_id": partner_id,
            "partner_name": partner_name,
            "created_at": datetime.now().isoformat()
        }), 201
        
    except Exception as e:
        print(f"채팅방 생성 에러: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/chat/rooms/<int:room_id>/messages', methods=['GET'])
def get_chat_messages(room_id):
    """메시지 목록 조회"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))
    offset = (page - 1) * limit
    
    try:
        conn, cur = conn_cur_create()
        
        # 채팅방 접근 권한 확인
        cur.execute("""
            SELECT user1_id, user2_id, user1_left, user2_left
            FROM chat_rooms
            WHERE id = %s
        """, (room_id,))
        room = cur.fetchone()
        
        if not room:
            return jsonify({"error": "Not found", "message": "Chat room not found"}), 404
        
        if user_id not in [room['user1_id'], room['user2_id']]:
            return jsonify({"error": "Forbidden", "message": "Cannot access this chat room"}), 403
        
        # 내가 나간 채팅방인지 확인
        if (user_id == room['user1_id'] and room['user1_left']) or \
           (user_id == room['user2_id'] and room['user2_left']):
            return jsonify({"error": "Forbidden", "message": "You have left this chat room"}), 403
        
        # 상대방이 나갔는지 확인
        is_partner_left = (room['user1_left'] if user_id == room['user2_id'] else room['user2_left'])
        
        # 메시지 조회 (최신 것부터)
        sql = """
        SELECT id, sender_id, content, is_read, sent_at
        FROM chat_messages
        WHERE room_id = %s
        ORDER BY sent_at DESC
        LIMIT %s OFFSET %s
        """
        cur.execute(sql, (room_id, limit, offset))
        messages = cur.fetchall()
        
        # 다음 페이지 확인
        cur.execute("SELECT COUNT(*) as cnt FROM chat_messages WHERE room_id = %s", (room_id,))
        total = cur.fetchone()['cnt']
        has_more = (offset + limit) < total
        
        result = []
        for msg in messages:
            result.append({
                "id": msg['id'],
                "sender_id": msg['sender_id'],
                "content": msg['content'],
                "is_read": bool(msg['is_read']),
                "created_at": msg['sent_at'].isoformat(),
                "is_mine": msg['sender_id'] == user_id
            })
        print(result)
        return jsonify({
            "messages": result,
            "has_more": has_more,
            "is_partner_left": bool(is_partner_left)
        })
        
    except Exception as e:
        print(f"메시지 조회 에러: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/chat/rooms/<int:room_id>/read', methods=['PUT'])
def mark_messages_read(room_id):
    """메시지 읽음 처리"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 채팅방 접근 권한 확인
        cur.execute("""
            SELECT user1_id, user2_id, user1_left, user2_left
            FROM chat_rooms
            WHERE id = %s
        """, (room_id,))
        room = cur.fetchone()
        
        if not room or user_id not in [room['user1_id'], room['user2_id']]:
            return jsonify({"error": "Forbidden", "message": "Cannot access this chat room"}), 403
        
        # 상대방이 보낸 미읽은 메시지 읽음 처리
        sql = """
        UPDATE chat_messages
        SET is_read = 1
        WHERE room_id = %s AND sender_id != %s AND is_read = 0
        """
        cur.execute(sql, (room_id, user_id))
        read_count = cur.rowcount
        conn.commit()
        
        # 읽음 처리된 메시지 ID 조회
        cur.execute("""
            SELECT id FROM chat_messages
            WHERE room_id = %s AND sender_id != %s AND is_read = 1
        """, (room_id, user_id))
        message_ids = [row['id'] for row in cur.fetchall()]
        
        # SocketIO로 상대방에게 알림
        partner_id = room['user2_id'] if user_id == room['user1_id'] else room['user1_id']
        socketio.emit('message_read', {
            'message_ids': message_ids
        }, room=f"user_{partner_id}")
        
        return jsonify({"success": True, "read_count": read_count})
        
    except Exception as e:
        print(f"읽음 처리 에러: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/chat/rooms/<int:room_id>/leave', methods=['DELETE'])
def leave_chat_room(room_id):
    """채팅방 나가기"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 채팅방 확인
        cur.execute("""
            SELECT user1_id, user2_id, user1_left, user2_left
            FROM chat_rooms
            WHERE id = %s
        """, (room_id,))
        room = cur.fetchone()
        
        if not room or user_id not in [room['user1_id'], room['user2_id']]:
            return jsonify({"error": "Forbidden", "message": "Cannot access this chat room"}), 403
        
        # 나가기 처리
        if user_id == room['user1_id']:
            cur.execute("UPDATE chat_rooms SET user1_left = 1 WHERE id = %s", (room_id,))
            # 상대방도 이미 나갔는지 확인
            if room['user2_left'] == 1:
                # 양쪽 모두 나간 경우 채팅방 삭제
                print(f"🗑️ 양쪽 모두 채팅방을 나감 - 채팅방 삭제: room_id={room_id}")
                cur.execute("DELETE FROM chat_rooms WHERE id = %s", (room_id,))
        else:
            cur.execute("UPDATE chat_rooms SET user2_left = 1 WHERE id = %s", (room_id,))
            # 상대방도 이미 나갔는지 확인
            if room['user1_left'] == 1:
                # 양쪽 모두 나간 경우 채팅방 삭제
                print(f"🗑️ 양쪽 모두 채팅방을 나감 - 채팅방 삭제: room_id={room_id}")
                cur.execute("DELETE FROM chat_rooms WHERE id = %s", (room_id,))
        
        conn.commit()
        
        return jsonify({"success": True, "message": "채팅방에서 나갔습니다"})
        
    except Exception as e:
        print(f"채팅방 나가기 에러: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/chat/unread-count', methods=['GET'])
def get_unread_count():
    """미확인 메시지 확인"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    user_id = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 미읽은 메시지가 있는지 확인
        sql = """
        SELECT COUNT(*) as cnt
        FROM chat_F cm
        JOIN chat_rooms cr ON cm.room_id = cr.id
        WHERE cm.sender_id != %s 
          AND cm.is_read = 0
          AND (cr.user1_id = %s OR cr.user2_id = %s)
          AND NOT (cr.user1_id = %s AND cr.user1_left = 1)
          AND NOT (cr.user2_id = %s AND cr.user2_left = 1)
        """
        cur.execute(sql, (user_id, user_id, user_id, user_id, user_id))
        count = cur.fetchone()['cnt']
        
        return jsonify({"has_unread": count > 0})
        
    except Exception as e:
        print(f"미확인 메시지 확인 에러: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    finally:
        if conn:
            conn.close()


# ==================== Socket.IO ====================

# 연결된 사용자 관리
connected_users = {}  # {user_id: sid}

@socketio.on('connect')
def handle_connect(auth):
    """소켓 연결"""
    print(f"📡 소켓 연결 시도: sid={request.sid}")
    print(f"   auth 파라미터: {type(auth)}, {auth}")
    
    try:
        # JWT 토큰 인증 (auth 파라미터에서 가져오기)
        token = None
        if auth and isinstance(auth, dict):
            token = auth.get('token')
            if token:
                print(f"🔑 auth에서 토큰 발견 (전체): {token}")
        
        # auth가 없으면 query parameter에서 시도 (호환성)
        if not token:
            token = request.args.get('token')
            if token:
                print(f"🔑 query에서 토큰 발견 (전체): {token}")
        
        if not token:
            print("❌ 토큰 없음: 연결 거부")
            return {'status': 'error', 'message': '인증 토큰이 필요합니다'}
        
        print(f"🔍 토큰 검증 시작...")
        print(f"   블랙리스트 확인: {token in token_blacklist}")
        if token in token_blacklist:
            expiry = token_blacklist[token]
            print(f"   ⚠️ 블랙리스트 토큰 사용 시도! 만료시간: {datetime.fromtimestamp(expiry).isoformat()}")
        
        payload = decode_jwt_simple(token)
        if not payload:
            print("❌ 잘못된 토큰: 연결 거부")
            return {'status': 'error', 'message': '유효하지 않은 토큰입니다'}
        
        user_id = payload['username']
        print(f"✅ 토큰 검증 성공: username={user_id}, role={payload.get('role')}, exp={payload.get('exp')}")
        connected_users[user_id] = request.sid
        
        # 사용자별 룸에 입장 (개인 알림용)
        socketio_join(f"user_{user_id}")
        
        print(f"✅ User {user_id} connected: {request.sid}")
        return {'status': 'ok', 'user_id': user_id}
        
    except Exception as e:
        print(f"❌ 연결 에러: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return {'status': 'error', 'message': '연결 중 오류가 발생했습니다'}


@socketio.on('disconnect')
def handle_disconnect():
    """소켓 연결 해제"""
    try:
        user_id = None
        for uid, sid in connected_users.items():
            if sid == request.sid:
                user_id = uid
                break
        
        if user_id:
            del connected_users[user_id]
            print(f"User {user_id} disconnected")
    except Exception as e:
        print(f"연결 해제 에러: {e}")


@socketio.on('join_room')
def handle_join_room(data):
    """채팅방 입장"""
    try:
        room_id = data['room_id']
        
        # 현재 연결된 사용자 확인
        user_id = None
        for uid, sid in connected_users.items():
            if sid == request.sid:
                user_id = uid
                break
        
        if not user_id:
            print(f"❌ 채팅방 입장 실패: 인증되지 않은 사용자")
            emit('error', {'message': '인증이 필요합니다'})
            return
        
        # 채팅방 참여자 확인
        try:
            conn, cur = conn_cur_create()
            sql = """
                SELECT user1_id, user2_id 
                FROM chat_rooms 
                WHERE id = %s;
            """
            cur.execute(sql, (room_id,))
            room = cur.fetchone()
            
            if not room:
                print(f"❌ 채팅방 입장 실패: 존재하지 않는 채팅방 {room_id}")
                emit('error', {'message': '존재하지 않는 채팅방입니다'})
                return
            
            # 참여자 확인
            if user_id not in [room['user1_id'], room['user2_id']]:
                print(f"❌ 채팅방 입장 거부: user={user_id}는 room {room_id}의 참여자가 아님")
                print(f"   채팅방 참여자: {room['user1_id']}, {room['user2_id']}")
                emit('error', {'message': '이 채팅방에 접근 권한이 없습니다'})
                return
            
        finally:
            conn.close()
        
        socketio_join(f"room_{room_id}")
        emit('join_room', {'success': True, 'room_id': room_id})
        print(f"✅ User {user_id} joined room {room_id}")
        
    except Exception as e:
        print(f"❌ 채팅방 입장 에러: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'message': str(e)})


@socketio.on('leave_room')
def handle_leave_room(data):
    """채팅방 퇴장"""
    try:
        room_id = data['room_id']
        socketio_leave(f"room_{room_id}")
        print(f"User left room {room_id}")
    except Exception as e:
        print(f"채팅방 퇴장 에러: {e}")


@socketio.on('send_message')
def handle_send_message(data):
    """메시지 전송"""
    try:
        room_id = data['room_id']
        content = data['content']
        
        # JWT에서 사용자 정보 가져오기 (connected_users에서 역조회)
        user_id = None
        for uid, sid in connected_users.items():
            if sid == request.sid:
                user_id = uid
                break
        
        if not user_id:
            emit('error', {'message': 'User not authenticated'})
            return
        
        conn, cur = conn_cur_create()
        
        # 채팅방 확인
        cur.execute("""
            SELECT user1_id, user2_id, user1_left, user2_left
            FROM chat_rooms
            WHERE id = %s
        """, (room_id,))
        room = cur.fetchone()
        
        if not room or user_id not in [room['user1_id'], room['user2_id']]:
            emit('error', {'message': 'Cannot access this chat room'})
            return
        
        # 상대방이 나갔는지 확인
        partner_id = room['user2_id'] if user_id == room['user1_id'] else room['user1_id']
        is_partner_left = (room['user1_left'] if user_id == room['user2_id'] else room['user2_left'])
        
        if is_partner_left:
            emit('error', {'message': 'Partner has left the chat room'})
            return
        
        # 메시지 저장
        sql = """
        INSERT INTO chat_messages (room_id, sender_id, content, sent_at)
        VALUES (%s, %s, %s, NOW())
        """
        cur.execute(sql, (room_id, user_id, content))
        conn.commit()
        message_id = cur.lastrowid
        
        # 채팅방 업데이트 시간 갱신
        cur.execute("UPDATE chat_rooms SET updated_at = NOW() WHERE id = %s", (room_id,))
        conn.commit()
        
        # 메시지 정보 조회
        cur.execute("""
            SELECT id, sender_id, content, is_read, sent_at
            FROM chat_messages
            WHERE id = %s
        """, (message_id,))
        message = cur.fetchone()
        
        # 메시지 데이터 생성 (양쪽 모두에게 receive_message로 전송)
        # 전송자에게는 is_mine: true
        message_data_sender = {
            "id": message['id'],
            "sender_id": message['sender_id'],
            "content": message['content'],
            "is_read": bool(message['is_read']),
            "created_at": message['sent_at'].isoformat(),
            "is_mine": True
        }
        
        # 상대방에게는 is_mine: false
        message_data_receiver = {
            "id": message['id'],
            "sender_id": message['sender_id'],
            "content": message['content'],
            "is_read": bool(message['is_read']),
            "created_at": message['sent_at'].isoformat(),
            "is_mine": False
        }
        
        # 본인에게 receive_message 전송
        emit('receive_message', message_data_sender)
        
        # 상대방에게 receive_message 전송
        emit('receive_message', message_data_receiver, room=f"room_{room_id}", skip_sid=request.sid)
        
        # ========== FCM 푸시 알림 발송 (상대방이 오프라인일 때만) ==========
        try:
            # 상대방이 현재 연결되어 있는지 확인
            partner_online = partner_id in connected_users
            
            if not partner_online:
                # 상대방이 오프라인이면 FCM 푸시 알림 발송
                # 발신자 이름 조회
                cur.execute("""
                    SELECT name, nickname FROM students WHERE student_number = %s
                    UNION
                    SELECT name, NULL FROM professors WHERE professor_number = %s
                    UNION
                    SELECT name, NULL FROM staff WHERE staff_number = %s
                    LIMIT 1
                """, (user_id, user_id, user_id))
                sender_info = cur.fetchone()
                
                if sender_info:
                    sender_name = sender_info.get('nickname') or sender_info.get('name') or '익명'
                    
                    fcm_manager.send_chat_message_notification(
                        recipient_id=partner_id,
                        sender_name=sender_name,
                        message_preview=content,
                        chat_room_id=room_id
                    )
                    print(f"📬 FCM 채팅 알림 발송: {sender_name} → {partner_id}")
                else:
                    print(f"⚠️ 발신자 정보 없음: {user_id}")
            else:
                print(f"✓ 상대방 온라인 상태 - FCM 발송 안 함: {partner_id}")
                
        except Exception as fcm_error:
            # FCM 알림 실패해도 메시지 전송은 성공 처리
            print(f"⚠️ FCM 채팅 알림 발송 실패 (메시지 전송은 성공): {fcm_error}")
            import traceback
            traceback.print_exc()
        
        conn.close()
        
    except Exception as e:
        print(f"메시지 전송 에러: {e}")
        emit('error', {'message': str(e)})


# ==================== 시간표 및 과제 관리 API ====================

# --- 1. 시간표 조회 ---
@app.route('/student/timetable', methods=['GET'])
def get_student_timetable():
    """학생 시간표 조회"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    year = request.args.get('year', type=int)
    semester = request.args.get('semester')  # "1", "2", "summer", "winter"
    
    if not year or not semester:
        return jsonify({"error": "year and semester are required"}), 400
    
    conn = None
    try:
        conn, cur = conn_cur_create()
        
        # 학생의 수강신청 강의 조회
        sql = """
        SELECT 
            l.id AS lecture_id,
            s.subject_code,
            s.name AS subject_name,
            p.professor_number,
            p.name AS professor_name,
            l.schedule,
            l.classroom,
            s.credits
        FROM enrollments e
        JOIN lectures l ON e.lecture_id = l.id
        JOIN subjects s ON l.subject_code = s.subject_code
        JOIN professors p ON l.professor_number = p.professor_number
        WHERE e.student_number = %s 
          AND l.year = %s 
          AND l.semester = %s
        ORDER BY l.id;
        """
        
        cur.execute(sql, (student_number, year, semester))
        lectures = cur.fetchall()
        
        print(f"lectures : {lectures}")
        return jsonify({"lectures": lectures}), 200
        
    except Exception as e:
        print(f"시간표 조회 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


# --- 2. 강의 상세 정보 조회 ---
@app.route('/student/lectures/<int:lecture_id>', methods=['GET'])
def get_lecture_detail(lecture_id):
    """강의 상세 정보 조회 (과목, 교수, 과제, 참고자료)"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 수강 권한 확인
        cur.execute("""
            SELECT id FROM enrollments 
            WHERE student_number = %s AND lecture_id = %s
        """, (student_number, lecture_id))
        
        if not cur.fetchone():
            return jsonify({"error": "Forbidden", "message": "Not enrolled in this lecture"}), 403
        
        # 강의 정보 조회
        cur.execute("""
            SELECT 
                s.name AS subject_name,
                l.schedule,
                l.classroom
            FROM lectures l
            JOIN subjects s ON l.subject_code = s.subject_code
            WHERE l.id = %s
        """, (lecture_id,))
        lecture = cur.fetchone()
        
        # 교수 정보 조회
        cur.execute("""
            SELECT 
                p.name,
                p.email,
                p.office_location AS office
            FROM lectures l
            JOIN professors p ON l.professor_number = p.professor_number
            WHERE l.id = %s
        """, (lecture_id,))
        professor = cur.fetchone()
        
        # 과제 목록 조회 (제출 상태 포함)
        cur.execute("""
            SELECT 
                a.id,
                a.title,
                a.description,
                a.due_date,
                a.created_at,
                a.reference_materials_file_path,
                s.submitted_at,
                CASE
                    WHEN s.id IS NULL THEN '미제출'
                    WHEN s.submitted_at <= a.due_date THEN '제출완료'
                    ELSE '지각제출'
                END AS status
            FROM assignments a
            LEFT JOIN submissions s ON a.id = s.assignment_id AND s.student_number = %s
            WHERE a.lecture_id = %s
            ORDER BY a.due_date DESC
        """, (student_number, lecture_id))
        assignments = cur.fetchall()
        
        # 참고자료 파일 파싱 (쉼표 구분)
        materials = []
        for assignment in assignments:
            if assignment.get('reference_materials_file_path'):
                file_paths = assignment['reference_materials_file_path'].split(',')
                for idx, file_path in enumerate(file_paths):
                    file_path = file_path.strip()
                    if file_path:
                        materials.append({
                            "id": f"{assignment['id']}_{idx}",
                            "assignment_id": assignment['id'],
                            "filename": os.path.basename(file_path),
                            "file_url": request.host_url.rstrip('/') + '/' + file_path,
                            "uploaded_at": assignment['created_at'].isoformat() if assignment.get('created_at') else None
                        })
            
            # 응답에서 reference_materials_file_path 제거 (materials에 파싱되어 있음)
            if 'reference_materials_file_path' in assignment:
                del assignment['reference_materials_file_path']
        
        # datetime을 ISO 형식으로 변환
        for assignment in assignments:
            if assignment.get('due_date'):
                assignment['due_date'] = assignment['due_date'].isoformat()
            if assignment.get('submitted_at'):
                assignment['submitted_at'] = assignment['submitted_at'].isoformat()
            if assignment.get('created_at'):
                assignment['created_at'] = assignment['created_at'].isoformat()
        
        return jsonify({
            "lecture": lecture,
            "professor": professor,
            "assignments": assignments,
            "materials": materials
        }), 200
        
    except Exception as e:
        print(f"강의 상세 조회 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# --- 2-1. 강의별 과제 목록 조회 ---
@app.route('/student/lectures/<int:lecture_id>/assignments', methods=['GET'])
def get_lecture_assignments(lecture_id):
    """특정 강의의 과제 목록 조회 (제출 상태 포함)"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    conn = None
    
    try:
        conn, cur = conn_cur_create()
        
        # 수강 여부 확인
        cur.execute("""
            SELECT 1 FROM enrollments 
            WHERE student_number = %s AND lecture_id = %s
        """, (student_number, lecture_id))
        
        if not cur.fetchone():
            return jsonify({"error": "Not enrolled in this lecture"}), 403
        
        # 과제 목록 및 제출 상태 조회
        cur.execute("""
            SELECT 
                a.id,
                a.title,
                a.description,
                a.due_date,
                a.created_at,
                CASE 
                    WHEN s.id IS NOT NULL THEN '제출'
                    ELSE '미제출'
                END as status,
                s.submitted_at
            FROM assignments a
            LEFT JOIN submissions s ON a.id = s.assignment_id 
                AND s.student_number = %s
            WHERE a.lecture_id = %s
            ORDER BY a.due_date ASC
        """, (student_number, lecture_id))
        
        assignments = cur.fetchall()
        
        # 날짜 형식 변환
        for assignment in assignments:
            assignment['due_date'] = assignment['due_date'].isoformat() if assignment['due_date'] else None
            assignment['created_at'] = assignment['created_at'].isoformat() if assignment['created_at'] else None
            assignment['submitted_at'] = assignment['submitted_at'].isoformat() if assignment['submitted_at'] else None
        
        print
        return jsonify({"assignments": assignments}), 200
        
    except Exception as e:
        print(f"Error in get_lecture_assignments: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()


# --- 2-2. 참고자료 다운로드 ---
@app.route('/student/materials/<string:material_id>/download', methods=['GET'])
def download_material(material_id):
    """참고자료 파일 다운로드"""
    print(f"📥 참고자료 다운로드 요청 - material_id: {material_id}")
    
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    print(f"   요청 학생: {student_number}")
    
    try:
        # material_id 파싱 (형식: "assignment_id_file_index")
        parts = material_id.split('_')
        if len(parts) < 2:
            print(f"❌ 잘못된 material_id 형식: {material_id}")
            return jsonify({"error": "Invalid material ID format"}), 400
        
        assignment_id = int(parts[0])
        file_index = int(parts[1])
        print(f"   파싱 결과 - assignment_id: {assignment_id}, file_index: {file_index}")
        
        conn, cur = conn_cur_create()
        
        # 과제 정보 조회
        cur.execute("""
            SELECT a.reference_materials_file_path, a.lecture_id
            FROM assignments a
            WHERE a.id = %s
        """, (assignment_id,))
        
        assignment = cur.fetchone()
        if not assignment:
            print(f"❌ 과제를 찾을 수 없음: assignment_id={assignment_id}")
            return jsonify({"error": "Assignment not found"}), 404
        
        print(f"   과제 정보: lecture_id={assignment['lecture_id']}, file_path={assignment['reference_materials_file_path']}")
        
        # 수강 권한 확인
        cur.execute("""
            SELECT id FROM enrollments 
            WHERE student_number = %s AND lecture_id = %s
        """, (student_number, assignment['lecture_id']))
        
        if not cur.fetchone():
            print(f"❌ 수강 권한 없음: student={student_number}, lecture={assignment['lecture_id']}")
            return jsonify({"error": "Forbidden", "message": "Not enrolled in this lecture"}), 403
        
        # 파일 경로 파싱
        if not assignment['reference_materials_file_path']:
            print(f"❌ 참고자료 없음")
            return jsonify({"error": "No materials found"}), 404
        
        file_paths = assignment['reference_materials_file_path'].split(',')
        print(f"   파일 목록: {file_paths}")
        
        if file_index >= len(file_paths):
            print(f"❌ 파일 인덱스 초과: file_index={file_index}, total={len(file_paths)}")
            return jsonify({"error": "File not found"}), 404
        
        file_path = file_paths[file_index].strip()
        # 윈도우/리눅스 경로 호환성: 백슬래시를 슬래시로 변환
        file_path = file_path.replace('\\', '/')
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_path)
        print(f"   파일 경로: {full_path}")
        
        # 파일 존재 여부 확인
        if not os.path.exists(full_path):
            print(f"❌ 파일이 서버에 없음: {full_path}")
            print(f"   UPLOAD_FOLDER: {app.config['UPLOAD_FOLDER']}")
            return jsonify({"error": "File not found on server", "path": file_path}), 404
        
        print(f"✅ 파일 다운로드 시작: {os.path.basename(file_path)}")
        
        # 파일 다운로드 응답
        return send_file(
            full_path,
            as_attachment=True,
            download_name=os.path.basename(file_path)
        )
        
    except ValueError as e:
        print(f"❌ ValueError: {e}")
        return jsonify({"error": "Invalid material ID"}), 400
    except Exception as e:
        print(f"❌ 참고자료 다운로드 에러: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()


# --- 4. 과제 제출 ---
@app.route('/student/assignments/<int:assignment_id>/submit', methods=['POST'])
def submit_assignment(assignment_id):
    """과제 제출"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    # 클라이언트는 'description' 필드로 보냄
    content = request.form.get('description', '')
    
    # 글자수 검증 (200자)
    if len(content) > 200:
        return jsonify({"error": "Content exceeds 200 characters"}), 400
    
    # 파일 업로드 처리 (클라이언트는 'files'로 보냄)
    uploaded_files = request.files.getlist('files')
    total_size = sum(file.content_length or 0 for file in uploaded_files)
    
    # 파일 크기 검증 (50MB)
    if total_size > 50 * 1024 * 1024:
        return jsonify({"error": "File size exceeds 50MB limit"}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        # 과제 정보 조회 (마감일 확인)
        cur.execute("""
            SELECT due_date, lecture_id FROM assignments WHERE id = %s
        """, (assignment_id,))
        assignment = cur.fetchone()
        
        if not assignment:
            return jsonify({"error": "Assignment not found"}), 404
        
        # 수강 권한 확인
        cur.execute("""
            SELECT id FROM enrollments 
            WHERE student_number = %s AND lecture_id = %s
        """, (student_number, assignment['lecture_id']))
        
        if not cur.fetchone():
            return jsonify({"error": "Forbidden"}), 403
        
        # 파일 저장
        file_paths = []
        if uploaded_files:
            submission_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'submissions', str(assignment_id), student_number)
            os.makedirs(submission_folder, exist_ok=True)
            
            for file in uploaded_files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    file_path = os.path.join(submission_folder, unique_filename)
                    file.save(file_path)
                    
                    # 상대 경로 저장
                    relative_path = file_path.replace('\\', '/').replace(app.config['UPLOAD_FOLDER'] + '/', '')
                    file_paths.append(relative_path)
        
        # 제출 상태 계산
        submitted_at = datetime.now()
        status = "제출완료" if submitted_at <= assignment['due_date'] else "지각제출"
        
        # DB 저장
        file_paths_str = ','.join(file_paths) if file_paths else None
        
        cur.execute("""
            INSERT INTO submissions (assignment_id, student_number, content, file_path, submitted_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (assignment_id, student_number, content, file_paths_str, submitted_at))
        
        conn.commit()
        submission_id = cur.lastrowid
        
        return jsonify({
            "submission_id": submission_id,
            "status": status,
            "submitted_at": submitted_at.isoformat()
        }), 201
        
    except Exception as e:
        print(f"과제 제출 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# --- 5. 과제 수정 ---
@app.route('/student/submissions/<int:submission_id>', methods=['PUT'])
def update_submission(submission_id):
    """과제 수정"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    # 클라이언트는 'description' 필드로 보냄
    content = request.form.get('description', '')
    
    if len(content) > 200:
        return jsonify({"error": "Content exceeds 200 characters"}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        # 제출물 소유자 확인
        cur.execute("""
            SELECT s.assignment_id, s.file_path, a.due_date
            FROM submissions s
            JOIN assignments a ON s.assignment_id = a.id
            WHERE s.id = %s AND s.student_number = %s
        """, (submission_id, student_number))
        
        submission = cur.fetchone()
        if not submission:
            return jsonify({"error": "Submission not found or unauthorized"}), 404
        
        # 기존 파일 경로
        existing_files = submission['file_path'].split(',') if submission['file_path'] else []
        
        # 삭제할 파일 처리 (클라이언트가 보내는 경우)
        delete_files = request.form.getlist('delete_files')
        if not delete_files:  # 배열 형식도 지원
            delete_files = request.form.getlist('delete_files[]')
        
        for delete_file in delete_files:
            if delete_file in existing_files:
                existing_files.remove(delete_file)
                # 실제 파일 삭제
                file_full_path = os.path.join(app.config['UPLOAD_FOLDER'], delete_file)
                if os.path.exists(file_full_path):
                    os.remove(file_full_path)
        
        # 신규 파일 업로드 (클라이언트는 'files'로 보냄)
        uploaded_files = request.files.getlist('files')
        total_size = sum(file.content_length or 0 for file in uploaded_files)
        
        if total_size > 50 * 1024 * 1024:
            return jsonify({"error": "File size exceeds 50MB limit"}), 400
        
        if uploaded_files:
            submission_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'submissions', 
                                            str(submission['assignment_id']), student_number)
            os.makedirs(submission_folder, exist_ok=True)
            
            for file in uploaded_files:
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    file_path = os.path.join(submission_folder, unique_filename)
                    file.save(file_path)
                    
                    relative_path = file_path.replace('\\', '/').replace(app.config['UPLOAD_FOLDER'] + '/', '')
                    existing_files.append(relative_path)
        
        # 상태 재계산
        updated_at = datetime.now()
        status = "제출완료" if updated_at <= submission['due_date'] else "지각제출"
        
        # DB 업데이트
        file_paths_str = ','.join(existing_files) if existing_files else None
        
        cur.execute("""
            UPDATE submissions 
            SET content = %s, file_path = %s, submitted_at = %s
            WHERE id = %s
        """, (content, file_paths_str, updated_at, submission_id))
        
        conn.commit()
        
        return jsonify({
            "submission_id": submission_id,
            "status": status,
            "updated_at": updated_at.isoformat()
        }), 200
        
    except Exception as e:
        print(f"과제 수정 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# --- 6. 과제 제출 내역 조회 ---
@app.route('/student/assignments/<int:assignment_id>/submission', methods=['GET'])
def get_submission(assignment_id):
    """과제 제출 내역 조회"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        cur.execute("""
            SELECT 
                s.id,
                s.content,
                s.file_path,
                s.submitted_at,
                CASE
                    WHEN s.submitted_at <= a.due_date THEN '제출완료'
                    ELSE '지각제출'
                END AS status
            FROM submissions s
            JOIN assignments a ON s.assignment_id = a.id
            WHERE s.assignment_id = %s AND s.student_number = %s
        """, (assignment_id, student_number))
        
        submission = cur.fetchone()
        
        if not submission:
            return jsonify({"message": "No submission found"}), 404
        
        # 파일 파싱
        files = []
        if submission['file_path']:
            file_paths = submission['file_path'].split(',')
            for idx, file_path in enumerate(file_paths):
                file_path = file_path.strip()
                if file_path:
                    files.append({
                        "id": idx,
                        "filename": os.path.basename(file_path),
                        "file_url": request.host_url.rstrip('/') + '/' + file_path,
                        "file_path": file_path  # 삭제 시 필요
                    })
        
        # 클라이언트 친화적으로 응답 구성
        response = {
            "submission_id": submission['id'],
            "description": submission['content'],  # content -> description으로 매핑
            "files": files,
            "submitted_at": submission['submitted_at'].isoformat(),
            "status": submission['status']
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"제출 내역 조회 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# --- 7. 전체 성적 조회 ---
@app.route('/student/grades', methods=['GET'])
def get_student_grades():
    """전체 성적 조회 (학기별)"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 학생의 학제 정보 조회
        cur.execute("""
            SELECT d.degree_type, s.department_code
            FROM students s
            JOIN departments d ON s.department_code = d.department_code
            WHERE s.student_number = %s
        """, (student_number,))
        
        student_info = cur.fetchone()
        degree_type = "2년제" if student_info['degree_type'] == 2 else "3년제"
        student_dept_code = student_info['department_code']
        
        # 성적 조회 (grade가 NULL인 현재 수강 중인 과목 제외)
        cur.execute("""
            SELECT 
                l.year,
                l.semester,
                sub.name AS subject_name,
                sub.department_code,
                sub.credits,
                e.grade,
                e.percentile
            FROM enrollments e
            JOIN lectures l ON e.lecture_id = l.id
            JOIN subjects sub ON l.subject_code = sub.subject_code
            WHERE e.student_number = %s
              AND e.grade IS NOT NULL
            ORDER BY l.year, 
                     FIELD(l.semester, '1학기', 'summer', '2학기', 'winter')
        """, (student_number,))
        
        grades = cur.fetchall()
        
        # 학기별 그룹화
        semesters_dict = {}
        total_major_credits = 0
        total_general_credits = 0
        total_grade_points = 0
        total_graded_credits = 0
        total_percentile_sum = 0
        total_percentile_count = 0
        
        grade_point_map = {
            'A+': 4.5, 'A0': 4.0,
            'B+': 3.5, 'B0': 3.0,
            'C+': 2.5, 'C0': 2.0,
            'D+': 1.5, 'D0': 1.0,
            'F': 0.0
        }
        
        for grade in grades:
            year = grade['year']
            semester = grade['semester']
            key = f"{year}_{semester}"
            
            if key not in semesters_dict:
                semesters_dict[key] = {
                    "year": year,
                    "semester": semester,
                    "courses": [],
                    "total_credits": 0,
                    "earned_credits": 0,
                    "grade_points": 0,
                    "graded_credits": 0,
                    "percentile_sum": 0,
                    "percentile_count": 0
                }
            
            # 전공/교양 구분
            # P/NP 과목: department_code가 NULL
            # 전공/교양: department_code로 구분 (학생의 학과코드와 같으면 전공, 다르면 교양)
            is_pnp = grade['department_code'] is None
            
            if is_pnp:
                # P/NP 과목은 별도 처리 (전공/교양 구분 없음)
                subject_type = "교양"  # P/NP는 일반적으로 교양으로 간주
            else:
                # 일반 과목: 학과 코드로 전공/교양 구분
                subject_type = "전공" if grade['department_code'] == student_dept_code else "교양"
            
            grade_value = grade['grade']
            grade_point = None
            credits = grade['credits']
            
            # P/NP 처리
            if is_pnp:
                # P/NP 과목도 신청 학점에는 포함
                semesters_dict[key]['total_credits'] += credits
                
                if grade_value == 'P':
                    semesters_dict[key]['earned_credits'] += credits
                    if subject_type == "전공":
                        total_major_credits += credits
                    else:
                        total_general_credits += credits
                # NP는 학점 인정 안 함 (신청은 했지만 취득하지 못함)
            else:
                # 일반 성적
                grade_point = grade_point_map.get(grade_value, 0)
                semesters_dict[key]['total_credits'] += credits
                
                if grade_value != 'F':
                    semesters_dict[key]['earned_credits'] += credits
                    if subject_type == "전공":
                        total_major_credits += credits
                    else:
                        total_general_credits += credits
                
                # 평점 계산 (F 포함)
                semesters_dict[key]['grade_points'] += grade_point * credits
                semesters_dict[key]['graded_credits'] += credits
                total_grade_points += grade_point * credits
                total_graded_credits += credits
            
            # 백분율 계산 (percentile 컬럼 사용 - P/NP 포함)
            if grade['percentile'] is not None:
                semesters_dict[key]['percentile_sum'] += grade['percentile']
                semesters_dict[key]['percentile_count'] += 1
                total_percentile_sum += grade['percentile']
                total_percentile_count += 1
            
            semesters_dict[key]['courses'].append({
                "subject_name": grade['subject_name'],
                "subject_type": subject_type,
                "credits": credits,
                "grade": grade_value,
                "grade_point": grade_point,
                "percentile": grade['percentile']
            })
        
        # 학기별 요약 계산
        semesters = []
        for sem in semesters_dict.values():
            gpa = sem['grade_points'] / sem['graded_credits'] if sem['graded_credits'] > 0 else 0
            percentage = sem['percentile_sum'] / sem['percentile_count'] if sem['percentile_count'] > 0 else 0
            
            sem['summary'] = {
                "total_credits": sem['total_credits'],
                "earned_credits": sem['earned_credits'],
                "percentage": round(percentage, 2),
                "gpa": round(gpa, 2)
            }
            
            del sem['grade_points']
            del sem['graded_credits']
            del sem['percentile_sum']
            del sem['percentile_count']
            semesters.append(sem)
        
        # 졸업 요건
        if degree_type == "2년제":
            required_total = 72
            required_major = 60
            required_general = 6
        else:  # 3년제
            required_total = 108
            required_major = 94
            required_general = 9
        
        overall_gpa = total_grade_points / total_graded_credits if total_graded_credits > 0 else 0
        overall_percentage = total_percentile_sum / total_percentile_count if total_percentile_count > 0 else 0
        
        print({
            "semesters": semesters,
            "total_summary": {
                "major_credits": total_major_credits,
                "general_credits": total_general_credits,
                "total_credits": total_major_credits + total_general_credits,
                "required_credits": required_total,
                "required_major": required_major,
                "required_general": required_general,
                "overall_gpa": round(overall_gpa, 2),
                "overall_percentage": round(overall_percentage, 2),
                "degree_type": degree_type
            }
        })
        return jsonify({
            "semesters": semesters,
            "total_summary": {
                "major_credits": total_major_credits,
                "general_credits": total_general_credits,
                "total_credits": total_major_credits + total_general_credits,
                "required_credits": required_total,
                "required_major": required_major,
                "required_general": required_general,
                "overall_gpa": round(overall_gpa, 2),
                "overall_percentage": round(overall_percentage, 2),
                "degree_type": degree_type
            }
        }), 200
        
    except Exception as e:
        print(f"성적 조회 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# --- 8. 졸업 요건 체크 ---
@app.route('/student/graduation-status', methods=['GET'])
def get_graduation_status():
    """졸업 가능 여부 확인"""
    payload, error = require_jwt(role=ROLE_STUDENT)
    if error:
        return error
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        # 학생의 학제 정보 조회
        cur.execute("""
            SELECT d.degree_type, s.department_code
            FROM students s
            JOIN departments d ON s.department_code = d.department_code
            WHERE s.student_number = %s
        """, (student_number,))
        
        student_info = cur.fetchone()
        degree_type = "2년제" if student_info['degree_type'] == 2 else "3년제"
        student_dept_code = student_info['department_code']
        
        # 이수 학점 계산 (grade가 NULL인 현재 수강 중인 과목 제외)
        cur.execute("""
            SELECT 
                sub.department_code,
                sub.credits,
                e.grade
            FROM enrollments e
            JOIN lectures l ON e.lecture_id = l.id
            JOIN subjects sub ON l.subject_code = sub.subject_code
            WHERE e.student_number = %s
              AND e.grade IS NOT NULL
        """, (student_number,))
        
        grades = cur.fetchall()
        
        major_credits = 0
        general_credits = 0
        
        for grade in grades:
            if grade['grade'] in ['F', 'NP']:
                continue
            
            credits = grade['credits']
            is_pnp = grade['department_code'] is None
            
            if is_pnp or grade['department_code'] != student_dept_code:
                general_credits += credits
            else:
                major_credits += credits
        
        total_credits = major_credits + general_credits
        
        # 졸업 요건
        if degree_type == "2년제":
            required_total = 72
            required_major = 60
            required_general = 6
        else:
            required_total = 108
            required_major = 94
            required_general = 9
        
        # 부족 학점 계산
        remaining_total = max(0, required_total - total_credits)
        remaining_major = max(0, required_major - major_credits)
        remaining_general = max(0, required_general - general_credits)
        
        is_eligible = (remaining_total == 0 and remaining_major == 0 and remaining_general == 0)
        
        # 메시지 생성
        messages = []
        if remaining_major > 0:
            messages.append(f"전공 {remaining_major}학점")
        if remaining_general > 0:
            messages.append(f"교양 {remaining_general}학점")
        if remaining_total > 0:
            messages.append(f"총 {remaining_total}학점")
        
        message = ", ".join(messages) + " 부족" if messages else "졸업 요건 충족"
        
        return jsonify({
            "degree_type": degree_type,
            "requirements": {
                "total": {
                    "required": required_total,
                    "earned": total_credits,
                    "remaining": remaining_total
                },
                "major": {
                    "required": required_major,
                    "earned": major_credits,
                    "remaining": remaining_major
                },
                "general": {
                    "required": required_general,
                    "earned": general_credits,
                    "remaining": remaining_general
                }
            },
            "is_eligible": is_eligible,
            "message": message
        }), 200
        
    except Exception as e:
        print(f"졸업 요건 체크 에러: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# ==================== 식단표 관련 ====================

# Google AI 클라이언트 초기화
genai_client = None
if google_ai_config.API_KEY:
    genai_client = genai.Client(api_key=google_ai_config.API_KEY)

# 식단 이미지 생성 프롬프트
MEAL_IMAGE_PROMPT = """음식들은 트레이에 담겨있어. 밥의 위치는 좌측 하단이야. 국의 위치는 우측 하단이야. 그 외의 메뉴들은 상단에 배치해. 각자 그릇에 담겨있고 그 그릇들은 트레이에 담겨있는거야. 오직 트레이와 음식만 나오는 이미지로 만들어. 비율은 1:1로 만들어줘. 배경 여백은 제거하고 오직 음식 이미지만 나와야해. 이미지에 글씨는 절대 넣지마."""

def get_week_date_range():
    """
    현재 날짜 기준으로 주간 식단표 날짜 범위 계산
    주말인 경우 다음 주 월요일 기준으로 계산
    Returns: (strDate, endDate) 형식의 YYYYMMDD 문자열 튜플
    """
    now = datetime.now()
    
    # 주말인 경우 다음 주 월요일로 이동
    if now.weekday() == 5:  # 토요일
        base_date = now + timedelta(days=2)
    elif now.weekday() == 6:  # 일요일
        base_date = now + timedelta(days=1)
    else:
        base_date = now
    
    # 해당 주의 일요일 계산 (weekday: 월=0, 일=6)
    days_from_sunday = (base_date.weekday() + 1) % 7
    sunday = base_date - timedelta(days=days_from_sunday)
    saturday = sunday + timedelta(days=6)
    
    str_date = sunday.strftime('%Y%m%d')
    end_date = saturday.strftime('%Y%m%d')
    
    return str_date, end_date

def fetch_meal_data_from_external_api():
    """
    인하공전 외부 API에서 식단표 데이터 가져오기
    Returns: 식단표 JSON 배열 또는 None (실패 시)
    """
    try:
        str_date, end_date = get_week_date_range()
        
        url = "https://www.inhatc.ac.kr/haksa/kr/getHaksaFoodMenuList"
        form_data = {
            'gubun': '학생',
            'strDate': str_date,
            'endDate': end_date
        }
        
        # TLS 1.2를 사용하는 세션 생성
        request_session = requests.Session()
        adapter = Tls12HttpAdapter()
        request_session.mount("https://", adapter)
        
        # 추가 헤더 설정
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        response = request_session.post(url, data=form_data, headers=headers, timeout=15)
        response.raise_for_status()
        
        meal_data = response.json()
        print(f"✅ 식단표 데이터 가져오기 성공: {len(meal_data)}일치")
        return meal_data
        
    except requests.exceptions.SSLError as e:
        print(f"❌ SSL 오류: {str(e)}")
        print("💡 HTTP로 재시도...")
        
        # SSL 오류 시 HTTP로 재시도
        try:
            http_url = "http://www.inhatc.ac.kr/haksa/kr/getHaksaFoodMenuList"
            response = requests.post(http_url, data=form_data, timeout=15)
            response.raise_for_status()
            meal_data = response.json()
            print(f"✅ 식단표 데이터 가져오기 성공 (HTTP): {len(meal_data)}일치")
            return meal_data
        except Exception as http_error:
            print(f"❌ HTTP 재시도 실패: {str(http_error)}")
            return None
            
    except Exception as e:
        print(f"❌ 식단표 데이터 가져오기 실패: {str(e)}")
        return None

def generate_meal_image(menu_text, meal_type, date_str):
    """
    Google AI를 사용하여 식단 이미지 생성
    Args:
        menu_text: 메뉴 텍스트 (예: "사골우거지국\\r\\n쌀밥\\r\\n김치전...")
        meal_type: 식사 유형 ("조식", "중식(일반)", "중식(특식)")
        date_str: 날짜 문자열 (YYYYMMDD)
    Returns: 이미지 파일 경로 또는 None
    """
    if not genai_client or not google_ai_config.API_KEY:
        print(f"❌ Google AI API Key가 설정되지 않았습니다.")
        return None
    
    try:
        # 메뉴 텍스트 정제 (\\r\\n 제거, 쉼표로 구분)
        menu_items = [item.strip() for item in menu_text.replace('\r\n', ',').split(',') if item.strip()]
        menu_str = ", ".join(menu_items)
        
        # 프롬프트 생성
        prompt = f"{menu_str} 메뉴로 메뉴판에 삽입할 이미지를 생성해줘. {MEAL_IMAGE_PROMPT}"
        
        print(f"🎨 이미지 생성 시작: {date_str} - {meal_type}")
        print(f"   메뉴: {menu_str[:50]}...")
        
        # Google AI로 이미지 생성
        # response = genai_client.models.generate_content(
        #     model="gemini-2.5-flash-image",
        #     contents=[prompt],
        # )
        
        # 이미지 추출 및 저장
        for part in response.candidates[0].content.parts:
            if part.inline_data is not None:
                image = Image.open(BytesIO(part.inline_data.data))
                
                # 저장 경로 생성 (meals 폴더 추가)
                date_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'meals', date_str)
                os.makedirs(date_folder, exist_ok=True)
                
                # 파일명 생성
                filename = f"{meal_type}.jpg"
                file_path = os.path.join(date_folder, filename)
                
                # 이미지 저장
                image.save(file_path, 'JPEG', quality=85)
                print(f"✅ 이미지 저장 완료: {file_path}")
                
                return file_path
        
        print(f"❌ 응답에 이미지가 없습니다.")
        return None
        
    except Exception as e:
        print(f"❌ 이미지 생성 실패 ({date_str} - {meal_type}): {str(e)}")
        return None

def generate_weekly_meal_images():
    """
    주간 식단표 이미지 자동 생성 (스케줄러용)
    매주 토요일 09:10에 실행
    """
    print("="*50)
    print(f"🍽️  주간 식단표 이미지 자동 생성 시작: {datetime.now()}")
    print("="*50)
    
    # 외부 API에서 식단 데이터 가져오기
    meal_data = fetch_meal_data_from_external_api()
    if not meal_data:
        print("❌ 식단 데이터를 가져올 수 없어 이미지 생성을 중단합니다.")
        return
    
    # 각 날짜별로 이미지 생성
    for day_meal in meal_data:
        date_str = day_meal.get('date')
        if not date_str:
            continue
        
        print(f"\n📅 {date_str} ({day_meal.get('day')}) 식단 이미지 생성 중...")
        
        # 조식 이미지 생성
        if day_meal.get('breakfast'):
            generate_meal_image(day_meal['breakfast'], '조식', date_str)
        
        # 중식(일반) 이미지 생성
        if day_meal.get('lunchNormal'):
            generate_meal_image(day_meal['lunchNormal'], '중식(일반)', date_str)
        
        # 중식(특식) 이미지 생성
        if day_meal.get('lunchSpecial'):
            generate_meal_image(day_meal['lunchSpecial'], '중식(특식)', date_str)
    
    print("\n" + "="*50)
    print(f"✅ 주간 식단표 이미지 생성 완료: {datetime.now()}")
    print("="*50)

@app.route('/student/meals', methods=['GET'])
def get_student_meals():
    """
    학생 식단표 조회 (이미지 포함)
    GET /student/meals
    """
    try:
        # 외부 API에서 식단 데이터 가져오기
        meal_data = fetch_meal_data_from_external_api()
        if not meal_data:
            return jsonify({
                'success': False,
                'message': '식단표 데이터를 가져올 수 없습니다.'
            }), 500
        
        # 각 날짜별로 이미지 URL 추가
        result = []
        base_url = request.host_url.rstrip('/')  # http://domain:port
        
        for day_meal in meal_data:
            date_str = day_meal.get('date')
            day = day_meal.get('day')
            
            # 이미지 URL 생성 (파일 존재 여부 확인)
            images = {}
            
            # 조식 이미지
            if day_meal.get('breakfast'):
                breakfast_img = os.path.join(app.config['UPLOAD_FOLDER'], 'meals', date_str, '조식.jpg')
                if os.path.exists(breakfast_img):
                    images['breakfast'] = f"{base_url}/uploads/meals/{date_str}/조식.jpg"
                else:
                    # 이미지가 없으면 생성 시도
                    generated_path = generate_meal_image(day_meal['breakfast'], '조식', date_str)
                    if generated_path:
                        images['breakfast'] = f"{base_url}/uploads/meals/{date_str}/조식.jpg"
                    else:
                        images['breakfast'] = None
            else:
                images['breakfast'] = None
            
            # 중식(일반) 이미지
            if day_meal.get('lunchNormal'):
                lunch_normal_img = os.path.join(app.config['UPLOAD_FOLDER'], 'meals', date_str, '중식(일반).jpg')
                if os.path.exists(lunch_normal_img):
                    images['lunchNormal'] = f"{base_url}/uploads/meals/{date_str}/중식(일반).jpg"
                else:
                    generated_path = generate_meal_image(day_meal['lunchNormal'], '중식(일반)', date_str)
                    if generated_path:
                        images['lunchNormal'] = f"{base_url}/uploads/meals/{date_str}/중식(일반).jpg"
                    else:
                        images['lunchNormal'] = None
            else:
                images['lunchNormal'] = None
            
            # 중식(특식) 이미지
            if day_meal.get('lunchSpecial'):
                lunch_special_img = os.path.join(app.config['UPLOAD_FOLDER'], 'meals', date_str, '중식(특식).jpg')
                if os.path.exists(lunch_special_img):
                    images['lunchSpecial'] = f"{base_url}/uploads/meals/{date_str}/중식(특식).jpg"
                else:
                    generated_path = generate_meal_image(day_meal['lunchSpecial'], '중식(특식)', date_str)
                    if generated_path:
                        images['lunchSpecial'] = f"{base_url}/uploads/meals/{date_str}/중식(특식).jpg"
                    else:
                        images['lunchSpecial'] = None
            else:
                images['lunchSpecial'] = None
            
            # 결과 데이터 구성
            meal_item = {
                'date': date_str,
                'day': day,
                'breakfast': {
                    'title': day_meal.get('breakfastTitle'),
                    'menu': day_meal.get('breakfast'),
                    'image': images['breakfast']
                },
                'lunchNormal': {
                    'title': day_meal.get('lunchNormalTitle'),
                    'menu': day_meal.get('lunchNormal'),
                    'image': images['lunchNormal']
                },
                'lunchSpecial': {
                    'title': day_meal.get('lunchSpecialTitle'),
                    'menu': day_meal.get('lunchSpecial'),
                    'image': images['lunchSpecial']
                },
                'lunchFast': {
                    'title': day_meal.get('lunchFastTitle'),
                    'menu': day_meal.get('lunchFast')
                }
            }
            
            result.append(meal_item)
        
        return jsonify({
            'success': True,
            'data': result
        }), 200
        
    except Exception as e:
        print(f"❌ 식단표 조회 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': '식단표 조회 중 오류가 발생했습니다.'
        }), 500

# ==================== 학교 공지 ====================
def parse_school_notice_html(html_content):
    """
    학교 공지 HTML을 파싱하여 공지 목록과 페이지 정보를 추출합니다.
    
    Args:
        html_content (str): HTML 문자열
        
    Returns:
        dict: {
            'notices': [...],
            'pagination': {
                'current_page': int,
                'total_pages': int,
                'total_count': int,
                'page_size': int
            }
        }
    """
    
    
    soup = BeautifulSoup(html_content, 'html.parser')
    notices = []
    
    # 공지사항 테이블 찾기
    table = soup.find('table', class_='board-table')
    if not table:
        return {'notices': [], 'pagination': {'current_page': 1, 'total_pages': 0, 'total_count': 0, 'page_size': 10}}
    
    tbody = table.find('tbody')
    if not tbody:
        return {'notices': [], 'pagination': {'current_page': 1, 'total_pages': 0, 'total_count': 0, 'page_size': 10}}
    
    # 각 공지사항 행 파싱
    rows = tbody.find_all('tr')
    for row in rows:
        try:
            cols = row.find_all('td')
            if len(cols) < 5:
                continue
            
            # 번호 (일반 공지는 숫자, 중요 공지는 특별 표시)
            num_col = cols[0]
            num_text = num_col.get_text(strip=True)
            
            # "공지" 또는 "일반공지" 등의 텍스트가 있으면 중요 공지
            is_important = not num_text.isdigit()
            
            # 제목 및 URL
            title_col = cols[1]
            title_link = title_col.find('a')
            if not title_link:
                continue
            
            title = title_link.get_text(strip=True)
            href = title_link.get('href', '')
            
            # href에서 공지 ID 추출: javascript:jf_combBbs_view('kr','2','33','103838')
            # 4번째 파라미터가 실제 공지 ID
            match = re.search(r"jf_combBbs_view\([^,]+,[^,]+,[^,]+,'(\d+)'\)", href)
            if match:
                notice_id = match.group(1)
            else:
                # 숫자 컬럼을 ID로 사용 (fallback)
                if num_text.isdigit():
                    notice_id = num_text
                else:
                    continue
            
            # 첨부파일 개수
            attachments = len(title_col.find_all('span', class_='icon-file'))
            
            # 작성일 (3번째 컬럼)
            date = cols[2].get_text(strip=True)
            
            # 조회수 (4번째 컬럼)
            views_text = cols[3].get_text(strip=True)
            views = int(views_text) if views_text.isdigit() else 0
            
            # 첨부파일 개수 (5번째 컬럼)
            attachments_text = cols[4].get_text(strip=True)
            attachments = int(attachments_text) if attachments_text.isdigit() else attachments
            
            notices.append({
                'id': notice_id,
                'title': title,
                'is_important': is_important,
                'date': date,
                'views': views,
                'attachments': attachments,
                'url': f'https://www.inhatc.ac.kr/combBbs/kr/2/33/{notice_id}/view.do'
            })
            
        except Exception as e:
            print(f"⚠️  공지사항 행 파싱 오류: {str(e)}")
            continue
    
    # 페이지 정보 파싱
    notice_count = len(notices)
    page_size = 10
    has_next_page = notice_count >= page_size  # 10개면 다음 페이지 존재
    
    pagination_info = {
        'current_page': 1,
        'page_size': page_size,
        'notice_count': notice_count,
        'has_next': has_next_page
    }
    
    # 페이지네이션 영역에서 현재 페이지 번호 추출
    paging_div = soup.find('div', class_='paging')
    if paging_div:
        current_span = paging_div.find('span', class_='current')
        if current_span:
            try:
                pagination_info['current_page'] = int(current_span.get_text(strip=True))
            except:
                pass
    
    return {
        'notices': notices,
        'pagination': pagination_info
    }

@app.route('/student/notices', methods=['GET'])
def get_school_notices():
    """
    학교 공지사항 목록을 조회합니다. (무한 스크롤 + 검색 지원)
    
    Query Parameters:
        page (int): 페이지 번호 (기본값: 1)
        search_type (str): 검색 필드 (sj=제목, writer=작성자, cn=내용, 기본값: sj)
        search_keyword (str): 검색어 (선택)
        
    Returns:
        {
            "success": true,
            "search": {
                "type": "sj",
                "keyword": "검색어"
            },
            "pagination": {
                "current_page": 1,
                "page_size": 10,
                "notice_count": 10,
                "has_next": true
            },
            "notices": [
                {
                    "id": "103838",
                    "title": "공지제목",
                    "is_important": false,
                    "date": "2025.11.07.",
                    "views": 29,
                    "attachments": 1,
                    "url": "https://www.inhatc.ac.kr/combBbs/kr/2/33/103838/view.do"
                }
            ]
        }
        
        pagination 설명:
        - current_page: 현재 페이지 번호
        - page_size: 페이지당 게시글 수 (고정값 10)
        - notice_count: 현재 페이지의 실제 게시글 수
        - has_next: 다음 페이지 존재 여부 (notice_count >= 10이면 true)
    """
    try:
        # 페이지 파라미터 (기본값: 1)
        page = request.args.get('page', default=1, type=int)
        
        # 검색 파라미터
        search_type = request.args.get('search_type', default='sj', type=str)  # sj=제목, writer=작성자, cn=내용
        search_keyword = request.args.get('search_keyword', default='', type=str)
        
        if page < 1:
            return jsonify({
                'success': False,
                'message': '페이지 번호는 1 이상이어야 합니다.'
            }), 400
        
        # 검색 타입 유효성 검사
        valid_search_types = ['sj', 'writer', 'cn']
        if search_type not in valid_search_types:
            return jsonify({
                'success': False,
                'message': f'검색 타입은 {", ".join(valid_search_types)} 중 하나여야 합니다.'
            }), 400
        
        # 학교 공지사항 설정
        notice_url = 'https://www.inhatc.ac.kr/combBbs/kr/2/list.do'
        layout_value = 'JtnwrEv85nDY%2BdkUleLFVw%3D%3D' # 고정값
        
        # 요청 데이터
        form_data = {
            'layout': layout_value,
            'bbsClSeq': '',
            'bbsOpenWrdSeq': '',
            'isViewMine': 'false',
            'page': str(page),
            'findType': search_type,
            'findWord': search_keyword
        }
        
        # TLS 1.2 어댑터를 사용한 세션 생성
        session = requests.Session()
        session.mount('https://', Tls12HttpAdapter())
        
        # 학교 서버에 요청
        response = session.post(
            notice_url,
            data=form_data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout=10
        )
        
        
        
        if response.status_code != 200:
            return jsonify({
                'success': False,
                'message': f'학교 서버 응답 오류 (HTTP {response.status_code})'
            }), 500
        
        # print(f"✅ 학교 공지 조회 성공 : {response.text}...")
        
        # HTML 파싱
        parsed_data = parse_school_notice_html(response.text)
        
        print(f"서버에서 응답해주는 데이터 : {parsed_data['notices']}")
        return jsonify({
            'success': True,
            'search': {
                'type': search_type,
                'keyword': search_keyword
            },
            'pagination': parsed_data['pagination'],
            'notices': parsed_data['notices']
        }), 200
        
    except requests.Timeout:
        return jsonify({
            'success': False,
            'message': '학교 서버 응답 시간 초과'
        }), 504
        
    except Exception as e:
        print(f"❌ 학교 공지 조회 오류: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': '학교 공지 조회 중 오류가 발생했습니다.'
        }), 500


# ==================== FCM 푸시 알림 API (학생 전용) ====================

# --- FCM 토큰 등록 ---
@app.route('/fcm/register', methods=['POST'])
def register_fcm_token():
    """
    FCM 디바이스 토큰 등록 (학생 전용)
    로그인 후 클라이언트에서 호출하여 토큰을 서버에 등록합니다.
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    data = request.get_json()
    device_token = data.get('device_token')
    device_type = data.get('device_type', 'android')  # android, ios, web
    
    if not device_token:
        return jsonify({"message": "device_token is required"}), 400
    
    if device_type not in ['android', 'ios', 'web']:
        return jsonify({"message": "Invalid device_type. Must be 'android', 'ios', or 'web'"}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        # 1. 기존 토큰 조회 (강제 로그아웃 알림 발송용)
        cur.execute("""
            SELECT device_token 
            FROM fcm_tokens 
            WHERE student_number = %s AND device_token != %s
        """, (student_number, device_token))
        existing_tokens = cur.fetchall()
        
        # 2. 기존 기기에 강제 로그아웃 FCM 발송
        force_logout_sent = False
        if existing_tokens:
            for token_row in existing_tokens:
                old_token = token_row['device_token']
                print(f"🔐 다른 기기 감지: 학생={student_number}, 기존 토큰={old_token[:20]}...")
                if fcm_manager.send_force_logout_fcm(old_token, "다른 기기에서 로그인되었습니다."):
                    force_logout_sent = True
        
        # 3. 이전 토큰 모두 삭제
        delete_sql = "DELETE FROM fcm_tokens WHERE student_number = %s"
        cur.execute(delete_sql, (student_number,))
        
        # 4. 새 토큰 등록
        insert_sql = """
            INSERT INTO fcm_tokens (student_number, device_token, device_type)
            VALUES (%s, %s, %s)
        """
        cur.execute(insert_sql, (student_number, device_token, device_type))
        conn.commit()
        
        if force_logout_sent:
            print(f"✅ FCM 토큰 등록: 학생={student_number}, type={device_type} (기존 기기 강제 로그아웃 알림 발송됨)")
        else:
            print(f"✅ FCM 토큰 등록: 학생={student_number}, type={device_type} (이전 토큰 삭제됨)")
        
        return jsonify({
            "message": "FCM token registered successfully",
            "student_number": student_number,
            "device_type": device_type,
            "force_logout_sent": force_logout_sent if existing_tokens else False
        }), 200
        
    except Exception as e:
        print(f"❌ FCM 토큰 등록 오류: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Failed to register FCM token"}), 500
    finally:
        conn.close()


# --- FCM 토큰 삭제 (로그아웃 시) ---
@app.route('/fcm/unregister', methods=['DELETE'])
def unregister_fcm_token():
    """
    FCM 디바이스 토큰 삭제 (학생 전용)
    로그아웃 시 호출하여 해당 디바이스의 푸시 알림을 중지합니다.
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    data = request.get_json()
    device_token = data.get('device_token')
    
    if not device_token:
        return jsonify({"message": "device_token is required"}), 400
    
    try:
        conn, cur = conn_cur_create()
        
        sql = "DELETE FROM fcm_tokens WHERE student_number = %s AND device_token = %s;"
        cur.execute(sql, (student_number, device_token))
        conn.commit()
        
        print(f"🗑️ FCM 토큰 삭제: 학생={student_number}, token={device_token[:20]}...")
        
        return jsonify({"message": "FCM token unregistered successfully"}), 200
        
    except Exception as e:
        print(f"❌ FCM 토큰 삭제 오류: {e}")
        return jsonify({"message": "Failed to unregister FCM token"}), 500
    finally:
        conn.close()


# --- 내 FCM 토큰 목록 조회 ---
@app.route('/fcm/tokens', methods=['GET'])
def get_my_fcm_tokens():
    """
    현재 로그인한 학생의 등록된 FCM 토큰 목록 조회
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        sql = """
            SELECT id, device_type, LEFT(device_token, 20) as token_preview, 
                   created_at, updated_at, last_used_at
            FROM fcm_tokens
            WHERE student_number = %s
            ORDER BY updated_at DESC
        """
        cur.execute(sql, (student_number,))
        tokens = cur.fetchall()
        
        # datetime을 ISO 형식 문자열로 변환
        for token in tokens:
            if token['created_at']:
                token['created_at'] = token['created_at'].isoformat()
            if token['updated_at']:
                token['updated_at'] = token['updated_at'].isoformat()
            if token.get('last_used_at'):
                token['last_used_at'] = token['last_used_at'].isoformat()
        
        return jsonify({
            "tokens": tokens,
            "total": len(tokens)
        }), 200
        
    except Exception as e:
        print(f"❌ FCM 토큰 조회 오류: {e}")
        return jsonify({"message": "Failed to get FCM tokens"}), 500
    finally:
        conn.close()


# --- 알림 설정 조회 ---
@app.route('/notifications/settings', methods=['GET'])
def get_notification_settings():
    """
    현재 학생의 알림 설정 조회
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        sql = """
            SELECT enable_all, enable_post_comment, enable_comment_reply, enable_chat_message
            FROM notification_settings
            WHERE student_number = %s
        """
        cur.execute(sql, (student_number,))
        settings = cur.fetchone()
        
        # 설정이 없으면 기본값 반환
        if not settings:
            settings = {
                'enable_all': True,
                'enable_post_comment': True,
                'enable_comment_reply': True,
                'enable_chat_message': True
            }
        else:
            # TINYINT(1)을 boolean으로 변환
            settings = {
                'enable_all': bool(settings['enable_all']),
                'enable_post_comment': bool(settings['enable_post_comment']),
                'enable_comment_reply': bool(settings['enable_comment_reply']),
                'enable_chat_message': bool(settings['enable_chat_message'])
            }
        
        return jsonify(settings), 200
        
    except Exception as e:
        print(f"❌ 알림 설정 조회 오류: {e}")
        return jsonify({"message": "Failed to get notification settings"}), 500
    finally:
        conn.close()


# --- 알림 설정 변경 (통합 엔드포인트) ---
@app.route('/notifications/settings', methods=['PUT'])
def update_notification_settings():
    """
    알림 설정 변경 (학생 전용)
    모든 알림 항목을 한 번에 업데이트할 수 있는 통합 엔드포인트
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    data = request.get_json()
    
    # 설정 가능한 필드들
    enable_all = data.get('enable_all')
    enable_post_comment = data.get('enable_post_comment')
    enable_comment_reply = data.get('enable_comment_reply')
    enable_chat_message = data.get('enable_chat_message')
    
    try:
        conn, cur = conn_cur_create()
        
        # 기존 설정이 있는지 확인
        cur.execute("SELECT student_number FROM notification_settings WHERE student_number = %s", (student_number,))
        existing = cur.fetchone()
        
        if existing:
            # 업데이트할 필드들을 동적으로 구성
            update_fields = []
            update_values = []
            
            if enable_all is not None:
                update_fields.append("enable_all = %s")
                update_values.append(1 if enable_all else 0)
            
            if enable_post_comment is not None:
                update_fields.append("enable_post_comment = %s")
                update_values.append(1 if enable_post_comment else 0)
            
            if enable_comment_reply is not None:
                update_fields.append("enable_comment_reply = %s")
                update_values.append(1 if enable_comment_reply else 0)
            
            if enable_chat_message is not None:
                update_fields.append("enable_chat_message = %s")
                update_values.append(1 if enable_chat_message else 0)
            
            if not update_fields:
                return jsonify({"message": "No fields to update"}), 400
            
            update_values.append(student_number)
            sql = f"""
                UPDATE notification_settings 
                SET {', '.join(update_fields)}
                WHERE student_number = %s
            """
            cur.execute(sql, tuple(update_values))
            
        else:
            # 새로 삽입
            sql = """
                INSERT INTO notification_settings 
                (student_number, enable_all, enable_post_comment, enable_comment_reply, enable_chat_message)
                VALUES (%s, %s, %s, %s, %s)
            """
            cur.execute(sql, (
                student_number,
                1 if enable_all is None or enable_all else 0,
                1 if enable_post_comment is None or enable_post_comment else 0,
                1 if enable_comment_reply is None or enable_comment_reply else 0,
                1 if enable_chat_message is None or enable_chat_message else 0
            ))
        
        conn.commit()
        
        print(f"✅ 알림 설정 변경: 학생={student_number}")
        print(f"   enable_all={enable_all}, post_comment={enable_post_comment}, comment_reply={enable_comment_reply}, chat={enable_chat_message}")
        
        return jsonify({"message": "Notification settings updated successfully"}), 200
        
    except Exception as e:
        print(f"❌ 알림 설정 변경 오류: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Failed to update notification settings"}), 500
    finally:
        conn.close()


# --- 알림 히스토리 조회 ---
@app.route('/notifications/history', methods=['GET'])
def get_notification_history():
    """
    알림 히스토리 조회 (페이지네이션) - 학생 전용
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    unread_only = request.args.get('unread_only', 'false').lower() == 'true'
    # unread_only 파라미터가 'true'이면 읽지 않은 알림만 필터링
    # 기본값은 false (알림 내역 전부 조회)
    limit = min(limit, 100)  # 최대 100개
    offset = (page - 1) * limit
    
    try:
        conn, cur = conn_cur_create()
        
        # 필터 조건
        # 1. 읽지 않은 알림: 무조건 표시
        # 2. 읽은 알림: read_at으로부터 24시간 이내만 표시
        where_clause = """
            WHERE student_number = %s 
            AND (
                is_read = 0 
                OR (is_read = 1 AND read_at >= DATE_SUB(NOW(), INTERVAL 1 DAY))
            )
        """
        params = [student_number]
        
        if unread_only: # 읽지 않은 알림만 필터링
            where_clause = "WHERE student_number = %s AND is_read = 0"
        
        # 전체 개수 조회
        count_sql = f"SELECT COUNT(*) as total FROM notification_history {where_clause}"
        cur.execute(count_sql, params)
        total = cur.fetchone()['total']
        
        print(f"{total}개의 알림 히스토리 조회")
        
        # 알림 목록 조회
        sql = f"""
            SELECT id, notification_type, title, body, data, sent_at, is_read, read_at
            FROM notification_history
            {where_clause}
            ORDER BY sent_at DESC
            LIMIT %s OFFSET %s
        """
        cur.execute(sql, params + [limit, offset])
        notifications = cur.fetchall()
        
        # datetime을 ISO 형식 문자열로 변환
        for noti in notifications:
            if noti['sent_at']:
                noti['sent_at'] = noti['sent_at'].isoformat()
            if noti.get('read_at'):
                noti['read_at'] = noti['read_at'].isoformat()
            noti['is_read'] = bool(noti['is_read'])
            # JSON 데이터 파싱
            if noti['data']:
                import json
                try:
                    noti['data'] = json.loads(noti['data'])
                except:
                    noti['data'] = {}
        
        return jsonify({
            "notifications": notifications,
            "pagination": {
                "current_page": page,
                "per_page": limit,
                "total": total,
                "total_pages": (total + limit - 1) // limit
            }
        }), 200
        
    except Exception as e:
        print(f"❌ 알림 히스토리 조회 오류: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Failed to get notification history"}), 500
    finally:
        conn.close()


# --- 알림 읽음 처리 ---
@app.route('/notifications/<int:notification_id>/read', methods=['PUT'])
def mark_notification_as_read(notification_id):
    """
    특정 알림을 읽음 처리 (학생 전용)
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        sql = """
            UPDATE notification_history 
            SET is_read = 1, read_at = CURRENT_TIMESTAMP
            WHERE id = %s AND student_number = %s
        """
        cur.execute(sql, (notification_id, student_number))
        conn.commit()
        
        if cur.rowcount == 0:
            return jsonify({"message": "Notification not found"}), 404
        
        return jsonify({"message": "Notification marked as read"}), 200
        
    except Exception as e:
        print(f"❌ 알림 읽음 처리 오류: {e}")
        return jsonify({"message": "Failed to mark notification as read"}), 500
    finally:
        conn.close()


# --- 모든 알림 읽음 처리 ---
@app.route('/notifications/read-all', methods=['PUT'])
def mark_all_notifications_as_read():
    """
    모든 알림을 읽음 처리 (학생 전용)
    """
    payload, error = require_jwt(role=ROLE_STUDENT)  # 학생만 허용
    if error or not payload:
        response, status_code = error
        return response, status_code
    
    student_number = payload['username']
    
    try:
        conn, cur = conn_cur_create()
        
        sql = """
            UPDATE notification_history 
            SET is_read = 1, read_at = CURRENT_TIMESTAMP 
            WHERE student_number = %s AND is_read = 0
        """
        cur.execute(sql, (student_number,))
        conn.commit()
        
        updated_count = cur.rowcount
        
        return jsonify({
            "message": "All notifications marked as read",
            "updated_count": updated_count
        }), 200
        
    except Exception as e:
        print(f"❌ 모든 알림 읽음 처리 오류: {e}")
        return jsonify({"message": "Failed to mark all notifications as read"}), 500
    finally:
        conn.close()


# 스케줄러 설정
scheduler = BackgroundScheduler()

# 주간 식단표 이미지 자동 생성 (매주 토요일 09:10)
scheduler.add_job(
    func=generate_weekly_meal_images,
    trigger=CronTrigger(day_of_week='sat', hour=9, minute=10),
    id='weekly_meal_image_generation',
    name='주간 식단표 이미지 자동 생성',
    replace_existing=True
)

# 만료된 FCM 토큰 자동 정리 (매일 새벽 3시)
scheduler.add_job(
    func=fcm_manager.clean_expired_fcm_tokens,
    trigger=CronTrigger(hour=3, minute=0),
    id='clean_expired_fcm_tokens',
    name='만료된 FCM 토큰 자동 정리 (60일 미사용)',
    replace_existing=True,
    kwargs={'days': 60}  # 60일(2개월) 미사용 토큰 삭제
)

# ==================== 서버 실행 ====================
if __name__ == '__main__':
    print("🚀 Flask-SocketIO 서버 시작...")
    print(f"   CORS: *")
    print(f"   Host: 0.0.0.0:5000")
    
    # 스케줄러 시작
    try:
        scheduler.start()
        print("⏰ 스케줄러 시작 완료")
        print("   - 매주 토요일 09:10: 식단표 이미지 자동 생성")
        print("   - 매일 새벽 03:00: 만료된 FCM 토큰 자동 정리 (60일 미사용)")
    except Exception as e:
        print(f"⚠️  스케줄러 시작 실패: {str(e)}")
    
    try:
        socketio.run(
            app, 
            debug=True, 
            host='0.0.0.0', 
            port=5000,
            allow_unsafe_werkzeug=True  # 개발 환경용
        )
    except (KeyboardInterrupt, SystemExit):
        # 서버 종료 시 스케줄러도 종료
        scheduler.shutdown()
        print("\n⏰ 스케줄러 종료 완료")