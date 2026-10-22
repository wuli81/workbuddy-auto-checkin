FROM python:3.12-slim

WORKDIR /app

COPY workbuddy_checkin.py workbuddy_auth.py workbuddy_decrypt.js .

RUN mkdir -p auths

# 默认每天 9 点签到
ENV CRON_HOUR=9
ENV TZ=Asia/Shanghai
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*

CMD ["python3", "workbuddy_checkin.py", "cron", "9"]

