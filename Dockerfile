# Python 3.10 베이스 이미지 사용
FROM python:3.10-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 도구 설치
# gcc, pkg-config: C 확장 빌드용
# default-libmysqlclient-dev: PyMySQL 빌드용
# curl: 헬스체크용
RUN apt-get update && apt-get install -y \
    gcc \
    pkg-config \
    default-libmysqlclient-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# requirements.txt 복사 및 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 파일 복사
COPY app.py .
COPY config.py .
COPY fcm_manager.py .
COPY meal_image_generator.py .
COPY AFIGserviceAccountKey.json .

# uploads 디렉토리 생성 (이미지 저장용)
RUN mkdir -p /app/uploads

# 포트 노출
EXPOSE 5000

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/ || exit 1

# 환경변수 기본값 설정
ENV PYTHONUNBUFFERED=1

# Gunicorn으로 Flask 앱 실행 (프로덕션)
# 개발 모드에서는 docker-compose.yml에서 command를 오버라이드합니다
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "eventlet", "--timeout", "120", "app:app"]
