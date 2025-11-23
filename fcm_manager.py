"""
FCM (Firebase Cloud Messaging) 관리 모듈 (학생 전용 앱)
학생들에게만 푸시 알림 발송
"""

from firebase_admin import messaging
import pymysql
from config import db_config as db
from datetime import datetime
import json

# Firebase는 app.py에서 이미 초기화됨


def get_db_connection():
    """데이터베이스 연결 생성"""
    conn = pymysql.connect(
        host=db.DB_HOST,
        port=db.DB_PORT,
        user=db.DB_USER,
        password=db.DB_PASSWORD,
        db=db.DB_DATABASE,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    return conn


def send_fcm_notification(student_number, title, body, notification_type, data=None):
    """
    특정 학생에게 FCM 푸시 알림 발송
    
    Args:
        student_number: 학번
        title: 알림 제목
        body: 알림 본문
        notification_type: 알림 타입 ('post_comment', 'comment_reply', 'chat_message')
        data: 추가 데이터 (딕셔너리)
    
    Returns:
        성공 여부 (bool)
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. 학생의 알림 설정 확인
        cur.execute("""
            SELECT enable_all, enable_post_comment, enable_comment_reply, enable_chat_message
            FROM notification_settings
            WHERE student_number = %s
        """, (student_number,))
        settings = cur.fetchone()
        
        # 알림 설정이 없으면 기본값으로 생성
        if not settings:
            cur.execute("""
                INSERT INTO notification_settings (student_number)
                VALUES (%s)
            """, (student_number,))
            conn.commit()
            # 기본값은 모두 True
            settings = {
                'enable_all': 1,
                'enable_post_comment': 1,
                'enable_comment_reply': 1,
                'enable_chat_message': 1
            }
        
        # 2. 알림 설정 확인 (전체 알림 off 또는 해당 타입 off면 발송 안 함)
        if not settings['enable_all']:
            print(f"⏸️ 학생 {student_number}: 전체 알림이 꺼져있음")
            return False
        
        type_map = {
            'post_comment': 'enable_post_comment',
            'comment_reply': 'enable_comment_reply',
            'chat_message': 'enable_chat_message'
        }
        
        if notification_type in type_map and not settings.get(type_map[notification_type], True):
            print(f"⏸️ 학생 {student_number}: {notification_type} 알림이 꺼져있음")
            return False
        
        # 3. 학생의 FCM 토큰 조회
        cur.execute("""
            SELECT device_token
            FROM fcm_tokens
            WHERE student_number = %s
        """, (student_number,))
        tokens = cur.fetchall()
        
        if not tokens:
            print(f"⚠️ 학생 {student_number}: FCM 토큰이 등록되지 않음")
            return False
        
        # 4. 알림 히스토리 먼저 저장 (notification_id를 FCM 메시지에 포함하기 위해)
        cur.execute("""
            INSERT INTO notification_history 
            (student_number, notification_type, title, body, data)
            VALUES (%s, %s, %s, %s, %s)
        """, (student_number, notification_type, title, body, json.dumps(data) if data else None))
        conn.commit()
        
        notification_id = cur.lastrowid  # 방금 저장된 알림 ID
        print(f"📝 알림 히스토리 저장: 학생={student_number}, type={notification_type}, id={notification_id}")
        
        # 5. data에 notification_id 추가
        fcm_data = data.copy() if data else {}
        fcm_data['notification_id'] = str(notification_id)  # ⭐ 클라이언트가 읽음 처리할 수 있도록
        
        # 6. FCM 메시지 생성 및 발송
        success_count = 0
        failed_tokens = []
        
        for token_row in tokens:
            device_token = token_row['device_token']
            
            # FCM 메시지 구성
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body
                ),
                data=fcm_data,  # notification_id 포함된 data
                token=device_token,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        sound='default',
                        channel_id='default'
                    )
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            sound='default',
                            badge=1
                        )
                    )
                )
            )
            
            try:
                response = messaging.send(message)
                print(f"✅ FCM 발송 성공: 학생={student_number}, token={device_token[:20]}..., response={response}")
                success_count += 1
                
                # 토큰 신선도 업데이트 (last_used_at)
                try:
                    cur.execute("""
                        UPDATE fcm_tokens 
                        SET last_used_at = CURRENT_TIMESTAMP 
                        WHERE device_token = %s
                    """, (device_token,))
                    conn.commit()
                except Exception as update_error:
                    print(f"⚠️ 토큰 신선도 업데이트 실패: {update_error}")
                
            except messaging.UnregisteredError:
                print(f"❌ 유효하지 않은 토큰 (UNREGISTERED): {device_token[:20]}...")
                failed_tokens.append(device_token)
            except messaging.InvalidArgumentException:
                print(f"❌ 잘못된 토큰 형식 (INVALID_ARGUMENT): {device_token[:20]}...")
                failed_tokens.append(device_token)
            except Exception as e:
                print(f"❌ FCM 발송 실패: {e}")
                # 다른 에러는 토큰 삭제 안 함 (일시적 네트워크 오류 등)
        
        # 5. 실패한 토큰 삭제 (UnregisteredError, InvalidArgumentException)
        if failed_tokens:
            placeholders = ','.join(['%s'] * len(failed_tokens))
            cur.execute(f"""
                DELETE FROM fcm_tokens
                WHERE device_token IN ({placeholders})
            """, failed_tokens)
            conn.commit()
            print(f"🗑️ 유효하지 않은 토큰 {len(failed_tokens)}개 삭제됨")
        
        return success_count > 0
        
    except Exception as e:
        print(f"❌ send_fcm_notification 오류: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if conn:
            conn.close()


# ============================================
# 각 이벤트별 알림 발송 함수
# ============================================

def send_post_comment_notification(post_author_id, commenter_name, post_title, post_id, comment_id, category_id):
    """
    게시글에 댓글이 달렸을 때 알림 발송
    
    Args:
        post_author_id: 게시글 작성자 학번
        commenter_name: 댓글 작성자 이름
        post_title: 게시글 제목
        post_id: 게시글 ID
        comment_id: 댓글 ID
        category_id: 게시글 카테고리 ID (페이지네이션용)
    """
    title = "새 댓글"
    body = f"{commenter_name}님이 '{post_title}' 게시글에 댓글을 남겼습니다."
    data = {
        'type': 'post_comment',
        'post_id': str(post_id),
        'comment_id': str(comment_id),
        'category_id': str(category_id)  # ⭐ 추가
    }
    
    return send_fcm_notification(
        student_number=post_author_id,
        title=title,
        body=body,
        notification_type='post_comment',
        data=data
    )


def send_comment_reply_notification(comment_author_id, replier_name, post_title, post_id, parent_comment_id, reply_id, category_id):
    """
    댓글에 대댓글이 달렸을 때 알림 발송
    
    Args:
        comment_author_id: 댓글 작성자 학번
        replier_name: 대댓글 작성자 이름
        post_title: 게시글 제목
        post_id: 게시글 ID
        parent_comment_id: 부모 댓글 ID
        reply_id: 대댓글 ID
        category_id: 게시글 카테고리 ID (페이지네이션용)
    """
    title = "새 답글"
    body = f"{replier_name}님이 내 댓글에 답글을 남겼습니다: '{post_title}'"
    data = {
        'type': 'comment_reply',
        'post_id': str(post_id),
        'comment_id': str(parent_comment_id),
        'reply_id': str(reply_id),
        'category_id': str(category_id)  # ⭐ 추가
    }
    
    return send_fcm_notification(
        student_number=comment_author_id,
        title=title,
        body=body,
        notification_type='comment_reply',
        data=data
    )


def send_chat_message_notification(recipient_id, sender_name, message_preview, chat_room_id):
    """
    채팅 메시지 알림 발송 (백그라운드 상태일 때)
    
    Args:
        recipient_id: 수신자 학번
        sender_name: 발신자 이름
        message_preview: 메시지 미리보기 (최대 50자)
        chat_room_id: 채팅방 ID
    """
    title = f"{sender_name}"
    body = message_preview[:50] + ('...' if len(message_preview) > 50 else '')
    data = {
        'type': 'chat_message',
        'chat_room_id': str(chat_room_id),
        'sender_id': str(sender_name)
    }
    
    return send_fcm_notification(
        student_number=recipient_id,
        title=title,
        body=body,
        notification_type='chat_message',
        data=data
    )


# ============================================
# 멀티캐스트 발송 (여러 학생에게 동시 발송)
# ============================================

def send_fcm_multicast(student_numbers, title, body, notification_type, data=None):
    """
    여러 학생에게 동시에 FCM 알림 발송
    
    Args:
        student_numbers: 학번 리스트
        title: 알림 제목
        body: 알림 본문
        notification_type: 알림 타입
        data: 추가 데이터
    
    Returns:
        성공 수 (int)
    """
    success_count = 0
    for student_number in student_numbers:
        if send_fcm_notification(student_number, title, body, notification_type, data):
            success_count += 1
    
    return success_count


# ============================================
# 만료된 토큰 자동 정리 (신선도 관리)
# ============================================

def clean_expired_fcm_tokens(days=60):
    """
    지정된 일수 동안 사용하지 않은 FCM 토큰 삭제
    
    Args:
        days: 만료 기준 일수 (기본 60일 = 2개월)
    
    Returns:
        삭제된 토큰 개수 (int)
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 지정된 일수 이상 사용하지 않은 토큰 삭제
        sql = """
            DELETE FROM fcm_tokens
            WHERE last_used_at < DATE_SUB(NOW(), INTERVAL %s DAY)
        """
        cur.execute(sql, (days,))
        conn.commit()
        
        deleted_count = cur.rowcount
        
        if deleted_count > 0:
            print(f"🧹 만료된 FCM 토큰 {deleted_count}개 삭제됨 (기준: {days}일 미사용)")
        
        return deleted_count
        
    except Exception as e:
        print(f"❌ FCM 토큰 정리 오류: {e}")
        import traceback
        traceback.print_exc()
        return 0
    finally:
        if conn:
            conn.close()

