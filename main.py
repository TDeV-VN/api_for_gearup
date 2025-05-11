# pip freeze > requirements.txt


from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import firebase_admin
from firebase_admin import credentials, auth
import datetime
import random
import string
import os
import redis
import yagmail
from dotenv import load_dotenv

# --- Cấu hình và Khởi tạo ---
load_dotenv() # Tải các biến từ file .env

SERVICE_ACCOUNT_KEY_PATH = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_PATH")
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_USERNAME = os.getenv("REDIS_USERNAME")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
GMAIL_USERNAME = os.getenv("GMAIL_USERNAME")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

# Khởi tạo Firebase Admin SDK
try:
    if not SERVICE_ACCOUNT_KEY_PATH:
        raise ValueError("FIREBASE_SERVICE_ACCOUNT_KEY_PATH không được đặt.")
    if not firebase_admin._apps:
        cred = credentials.Certificate(SERVICE_ACCOUNT_KEY_PATH)
        firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"Lỗi khởi tạo Firebase Admin SDK: {e}")
    # exit()

# Khởi tạo Redis client
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True, username=REDIS_USERNAME, password=REDIS_PASSWORD)
    redis_client.ping() # Kiểm tra kết nối
    print("Kết nối Redis thành công!")
except redis.exceptions.ConnectionError as e:
    print(f"Lỗi kết nối Redis: {e}")
    # exit()

# Khởi tạo yagmail (để gửi email)
try:
    if not GMAIL_USERNAME or not GMAIL_APP_PASSWORD:
        raise ValueError("GMAIL_USERNAME hoặc GMAIL_APP_PASSWORD không được đặt.")
    yag = yagmail.SMTP(GMAIL_USERNAME, GMAIL_APP_PASSWORD)
    print("Kết nối yagmail SMTP thành công!")
except Exception as e:
    print(f"Lỗi khởi tạo yagmail SMTP: {e}")
    # exit()


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---
class EmailRequest(BaseModel):
    email: EmailStr

class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp: str

# --- Hằng số ---
OTP_EXPIRY_SECONDS = 10 * 60  # OTP hết hạn sau 10 phút (600 giây)
REDIS_OTP_PREFIX = "otp_reset:" # Tiền tố cho key OTP trong Redis
REDIS_OOB_PREFIX = "oob_reset:" # Tiền tố cho key oobCode trong Redis

# --- Hàm tiện ích ---
def generate_otp(length: int = 4) -> str:
    return "".join(random.choices(string.digits, k=length))

async def send_email_with_otp_gmail(email_to: str, otp: str):
    subject = "Mã OTP Đặt Lại Mật Khẩu GearUp"
    body = f"""
    Chào bạn,

    Mã OTP để đặt lại mật khẩu của bạn là: {otp}

    Mã này sẽ hết hạn sau {OTP_EXPIRY_SECONDS // 60} phút.
    Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.

    Trân trọng,
    Đội ngũ GearUp
    """
    try:
        yag.send(to=email_to, subject=subject, contents=body)
        print(f"Đã gửi email OTP tới: {email_to}")
        return True
    except Exception as e:
        print(f"Lỗi khi gửi email OTP tới {email_to}: {e}")
        return False

# --- API Endpoints ---

@app.post("/request-password-otp-and-code", status_code=status.HTTP_200_OK)
async def request_password_otp_and_code(request: EmailRequest):
    email = request.email
    try:
        user = auth.get_user_by_email(email)
    except auth.UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email không tồn tại.")
    except Exception as e:
        print(f"Lỗi get_user_by_email: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi máy chủ khi kiểm tra email.")

    try:
        link = auth.generate_password_reset_link(email)
        if "oobCode=" not in link:
            raise ValueError("Không thể tạo link reset.")
        oob_code_start = link.find("oobCode=") + len("oobCode=")
        oob_code_end = link.find("&", oob_code_start)
        oob_code = link[oob_code_start:oob_code_end if oob_code_end != -1 else None]
        if not oob_code:
            raise ValueError("Không thể trích xuất oobCode.")
    except Exception as e:
        print(f"Lỗi generate_password_reset_link hoặc trích xuất oobCode: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi tạo mã đặt lại.")

    otp = generate_otp(length=4)

    # Lưu OTP và oobCode vào Redis với thời gian hết hạn
    # Key cho OTP: otp_reset:email@example.com
    # Key cho oobCode: oob_reset:email@example.com (sẽ được lấy sau khi OTP đúng)
    try:
        # Lưu OTP, sẽ được kiểm tra trước
        redis_client.setex(f"{REDIS_OTP_PREFIX}{email}", OTP_EXPIRY_SECONDS, otp)
        # Lưu oobCode, sẽ được trả về nếu OTP đúng
        redis_client.setex(f"{REDIS_OOB_PREFIX}{email}", OTP_EXPIRY_SECONDS, oob_code) # oobCode cũng có thể hết hạn theo OTP
        print(f"Đã lưu vào Redis cho {email}: OTP={otp}, oobCode={oob_code[:10]}...")
    except redis.exceptions.RedisError as e:
        print(f"Lỗi Redis khi lưu trữ: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi lưu trữ tạm thời.")


    email_sent = await send_email_with_otp_gmail(email, otp)
    if not email_sent:
        # Nếu không gửi được email, xóa key khỏi Redis
        redis_client.delete(f"{REDIS_OTP_PREFIX}{email}")
        redis_client.delete(f"{REDIS_OOB_PREFIX}{email}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi gửi email OTP.")

    return {"message": f"OTP đã được gửi tới {email}. Vui lòng kiểm tra email."}


@app.post("/verify-otp-and-get-code", status_code=status.HTTP_200_OK)
async def verify_otp_and_get_code(request: VerifyOtpRequest):
    email = request.email
    submitted_otp = request.otp

    try:
        stored_otp = redis_client.get(f"{REDIS_OTP_PREFIX}{email}")
    except redis.exceptions.RedisError as e:
        print(f"Lỗi Redis khi lấy OTP: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi truy xuất dữ liệu.")

    if not stored_otp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP không tồn tại hoặc đã hết hạn. Vui lòng yêu cầu mã mới.")

    if stored_otp != submitted_otp:
        # (Tùy chọn) Có thể thêm logic đếm số lần nhập sai và khóa tạm thời
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Mã OTP không chính xác.")

    # OTP hợp lệ, lấy oobCode
    try:
        oob_code_to_return = redis_client.get(f"{REDIS_OOB_PREFIX}{email}")
        if not oob_code_to_return:
            # Trường hợp này không nên xảy ra nếu logic lưu trữ ở trên là đúng
            # (oobCode nên được lưu cùng lúc với OTP)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi: Không tìm thấy mã đặt lại tương ứng.")
    except redis.exceptions.RedisError as e:
        print(f"Lỗi Redis khi lấy oobCode: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Lỗi truy xuất mã đặt lại.")


    # Xóa OTP và oobCode khỏi Redis sau khi đã xác thực thành công
    try:
        redis_client.delete(f"{REDIS_OTP_PREFIX}{email}")
        redis_client.delete(f"{REDIS_OOB_PREFIX}{email}")
    except redis.exceptions.RedisError as e:
        print(f"Lỗi Redis khi xóa key: {e}")
        # Không raise HTTP Exception ở đây, vì OTP đã đúng, chỉ là lỗi dọn dẹp

    print(f"OTP cho {email} đã được xác thực. Trả về oobCode.")
    return {"message": "OTP xác thực thành công.", "oobCode": oob_code_to_return}