FROM python:3

ARG DJANGO_SECRET_KEY
ARG DJANGO_ALLOWED_HOSTS
ARG DJANGO_CSRF_TRUSTED_ORIGINS
ARG DJANGO_SUPERUSER_USERNAME
ARG DJANGO_SUPERUSER_PASSWORD
ARG DJANGO_SUPERUSER_EMAIL
ARG POSTGRES_USER
ARG POSTGRES_PASSWORD
ARG POSTGRES_HOST

ENV PYTHONUNBUFFERED 1
ENV DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}
ENV DJANGO_ALLOWED_HOSTS=${DJANGO_ALLOWED_HOSTS}
ENV DJANGO_CSRF_TRUSTED_ORIGINS=${DJANGO_CSRF_TRUSTED_ORIGINS}
ENV DJANGO_SUPERUSER_USERNAME=${DJANGO_SUPERUSER_USERNAME}
ENV DJANGO_SUPERUSER_PASSWORD=${DJANGO_SUPERUSER_PASSWORD}
ENV DJANGO_SUPERUSER_EMAIL=${DJANGO_SUPERUSER_EMAIL}
ENV POSTGRES_USER=${POSTGRES_USER}
ENV POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
ENV POSTGRES_HOST=${POSTGRES_HOST}

# ディレクトリ作成
RUN mkdir /code

# ディレクトリ変更
WORKDIR /code

# requirements.txt をコピー
COPY requirements.txt /code/

# パッケージインストール
RUN pip install -r requirements.txt

# プロジェクトファイルをコピー
COPY . /code/

# 公開ポート
EXPOSE 8000

# 起動コマンド
CMD ["sh", "-c", "python manage.py migrate &&  python manage.py runserver 0.0.0.0:8000"]
