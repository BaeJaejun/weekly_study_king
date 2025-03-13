import jwt
from flask import Flask, render_template, request, redirect, session, url_for, flash, make_response
from pymongo import MongoClient
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler #pip install APScheduler
import pytz 
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your-super-secret-key"  # 세션 쓰기를 위한 시크릿 키
jwt_secret_key_access = "apple" # jwt 시크릿 access 키
jwt_secret_key_refresh = 'banana' #jwt refresh 키
client = MongoClient('mongodb://test:test@localhost', 27017 )  # MongoDB는 27017 포트로 돌아갑니다.
db = client.week_study_king  # 사용할 데이터베이스

# 사용할 타임존 지정 (예: 아시아/서울)----------------초기화 관련
tz = pytz.timezone('Asia/Seoul')

def reset_enter_time():
    """
    매일 자정에 실행되어, 모든 사용자의 enter_time을 초기화합니다.
    (만약 이미 오늘 날짜가 아니라면 enter_time을 None으로 설정할 수 있습니다.
    전체 초기화를 수행합니다.)
    """
    # 모든 사용자의 enter_time을 None으로 초기화
    result = db.users.update_many({}, {"$set": {"enter_time": None}})
    print(f"[{datetime.now(tz)}] reset_enter_time: {result.modified_count} users updated.")

def reset_study_time():
    """
    매주 월요일 자정에 실행되어, 모든 사용자의 study_time을 0으로 초기화합니다.
    """
    result = db.users.update_many({}, {"$set": {"study_time": 0}})
    print(f"[{datetime.now(tz)}] reset_study_time: {result.modified_count} users updated.")

# APScheduler BackgroundScheduler 설정 (타임존 설정)
scheduler = BackgroundScheduler(timezone=tz)

# 매일 자정(00:00)에 enter_time 초기화
scheduler.add_job(reset_enter_time, 'cron', hour=0, minute=0)

# 매주 월요일 자정(00:00)에 study_time 초기화
scheduler.add_job(reset_study_time, 'cron', day_of_week='mon', hour=0, minute=0)



# Flask 애플리케이션 시작 전에 스케줄러 시작
@app.before_request
def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        print("Scheduler started.")
        
# JWT 토큰을 검증하고 사용자 아이디를 반환하는 헬퍼 함수
def get_user_from_jwt():
    access_token = session.get("jwt_access")
    refresh_token = request.cookies.get("refresh_token")
    if not access_token:
        if refresh_token:
            print("디버깅-엑세스 토큰 없음/ 재발급시도") #refresh만 있을때 재발급 가능 
            return "EXPIRED✍"
        else:
            return None
        
    try:
        print("디버깅- 토큰 디코딩 시도")
        access_payload = jwt.decode(access_token, jwt_secret_key_access, algorithms=['HS256'])
        print(f"디버깅- payload: {access_payload}")

        return access_payload.get('id')
    except jwt.ExpiredSignatureError:
        print("엑세스토큰이 만료되었습니다. 다시 로그인 해주세요.", "danger")
        session.pop("jwt_access", None)
        return "EXPIRED✍"
    except jwt.InvalidTokenError:
        flash("유효하지 않은 토큰입니다.", "danger")
        session.pop("jwt_access", None)
        return None



# 메인페이지 및 입실/퇴실 상태, 상위 랭킹 5명 관리
@app.route('/')
def home():
    userid = get_user_from_jwt()
    #if not userid: # userid == None
    #    flash("로그인 후 이용해주세요.", "danger")
    #    return redirect(url_for("login"))
    if userid == "EXPIRED✍":
        print("Access Token이 만료됨. refresh token으로 재발급합니다.")
        return redirect(url_for("refresh"))
    
    elif userid:
        user = db.users.find_one({"userid": userid})
        if not user:
            flash("사용자 정보를 찾을 수 없습니다.", "danger")
            return redirect(url_for("home"))
    else:
        user = None
        
    now = datetime.now()
    today = now.date()
    
    # 입실 상태 확인
    enter_time = user.get("enter_time") if user else None
    can_checkin = user and enter_time is None
    can_checkout = user and enter_time and enter_time.date() == today

    # 상위 5명의 사용자 조회 (공부 시간 기준 내림차순)
    top_users = list(db.users.find({}, {"userid": 1, "username": 1, "study_time": 1})
                     .sort("study_time", -1)
                     .limit(5))
    for u in top_users:
        total_seconds = u.get("study_time", 0)
        u["hours"] = int(total_seconds // 3600)
        u["minutes"] = int((total_seconds % 3600) // 60)
        u["seconds"] = int(total_seconds % 60)

    return render_template("Rank.html",
                           can_checkin=can_checkin,
                           can_checkout=can_checkout,
                           is_logged_in= bool(user),
                           rankings=top_users)

# 입/퇴실 관련 라우트
@app.route('/check_in_out', methods=["POST"])
def check_in_out():
    userid = get_user_from_jwt()
    if not userid:
        flash("로그인 후 이용해주세요.", "danger")
        return redirect(url_for("login"))
    elif userid == "EXPIRED✍":
        print("Access Token이 만료됨. refresh token으로 재발급합니다.")
        return redirect(url_for("refresh")) #프론트 백 2개 다 버튼 클릭 방지지
    
    action = request.form.get("action")
    now = datetime.now()
    user = db.users.find_one({"userid": userid})
    
    if not user:
        flash("사용자를 찾을 수 없습니다.", "danger")
        return redirect(url_for("home"))
    
    # 입실 처리
    if action == "checkin":
        if user.get("enter_time") is None:
            db.users.update_one(
                {"userid": userid},
                {"$set": {"enter_time": now}}
            )
            flash("입실 완료!", "success")
        else:
            flash("이미 입실 중입니다.", "warning")
    
    # 퇴실 처리
    elif action == "checkout":
        enter_time = user.get("enter_time")
        if enter_time:
            duration = (now.replace(tzinfo=None) - enter_time).total_seconds()
            db.users.update_one(
                {"userid": userid},
                {
                    "$inc": {"study_time": int(duration)},
                    "$set": {"enter_time": None}
                }
            )
            flash(f"퇴실 완료! 오늘 공부한 시간: {int(duration // 3600)}시간 {int((duration % 3600) // 60)}분 {int(duration % 60)}초", "success")
        else:
            flash("입실 기록이 없습니다.", "warning")
    
    return redirect(url_for("home"))

# 로그인 관련 라우트
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        userid = request.form.get('userid')
        password = request.form.get('password')
        
        user = db.users.find_one({"userid": userid})
        if user and check_password_hash(user["password"], password):
            access_payload = {
                'id': userid,
                'exp': datetime.utcnow() + timedelta(minutes=30)  # access 토큰 만료 시간을 30분으로 설정
            }
            refresh_payload = {
                'id': userid,
                'exp': datetime.utcnow() + timedelta(days=7)  # refresh토큰 만료 시간을 7일으로 설정---토큰의 만료기각 쿠키가 토큰을 포함함
            }
            access_token = jwt.encode(access_payload, jwt_secret_key_access , algorithm='HS256')
            refresh_token = jwt.encode(refresh_payload, jwt_secret_key_refresh, algorithm='HS256')
            
            #플라스크 세션 == 클라이언트의 쿠키에 access token 저장
            session['jwt_access'] = access_token
            #클라이언트의 httponly쿠키 와 DB에 refresh token 저장
            db.users.update_one({"userid": userid}, {"$set": {"refresh_token": refresh_token}})
            response = make_response(redirect(url_for("home")))

            response.set_cookie(
                "refresh_token",
                refresh_token,
                httponly=True,       # JS 접근 불가
                secure=False,        # 로컬 테스트면 False (운영 환경은 True로)
                samesite="Strict",   # CSRF 방지
                max_age=60*60*24*7   # 7일 ---쿠키의 만료기간간
            )
            flash("로그인 성공!")

            return response
            
        else:
            flash("로그인 실패", "danger")
    
    return render_template("Login.html")


#access 토큰 만료시 refresh을 이용해 토큰 재발급
@app.route('/refresh', methods=["GET","POST"])
def refresh():
    # 클라이언트의 리프레쉬 토큰 가져오기
    client_refresh_token = request.cookies.get("refresh_token")
    
    try:
        payload = jwt.decode(client_refresh_token, jwt_secret_key_refresh, algorithms=["HS256"])
        userid = payload.get("id")
        user = db.users.find_one({"userid": userid})
        #DB에 저장된 리프레쉬 토큰 가져오기
        stored_refresh_token = user.get("refresh_token")
        
        if client_refresh_token != stored_refresh_token:
            flash("위조된 토큰입니다. 다시 로그인 해주세요.", "danger")
            session.clear()
            return redirect(url_for("login"))
        
        #엑세스 토큰 새로 발급
        new_access = jwt.encode({
            "id": userid,
            "exp": datetime.utcnow() + timedelta(minutes=30)
        }, jwt_secret_key_access, algorithm="HS256")
        session["jwt_access"] = new_access
        print("엑세스 토큰이 재발급 되었습니다.")
        resp = make_response(redirect(url_for("home")))
        return resp
    
    except jwt.ExpiredSignatureError:
         # 토큰은 만료되었지만, payload를 강제로 파싱해 ID만 가져오기
        try:
            payload = jwt.decode(client_refresh_token, jwt_secret_key_refresh, algorithms=["HS256"], options={"verify_exp": False})#유효한 유효기간 없으면 만료된거에서 아이디 못뽑아 그래서 False하면 뽑아
            userid = payload.get("id")
            db.users.update_one({"userid": userid}, {"$unset": {"refresh_token": ""}})
        except Exception:
            pass  # 안전장치 (토큰이 너무 손상됐을 경우)
#너무 손상되면 db에 찌꺼기 남음음
        print("Refresh Token이 만료되었습니다. 다시 로그인해주세요.", "danger")
        session.clear()
        response = make_response(redirect(url_for("home")))
        response.delete_cookie("refresh_token")
        return response
    
# 회원가입 관련 라우트
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        userid = request.form.get('userid')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if db.users.find_one({"userid": userid}):
            flash("중복된 아이디가 존재합니다. 다른 아이디를 입력해주세요.")
            return redirect(url_for("register"))
        if password != confirm_password:
            flash("비밀번호가 일치하지 않습니다.")
            return redirect(url_for("register"))
        
        hashed_pw = generate_password_hash(password)
        user = {
            'username': username,
            "userid": userid,
            'password': hashed_pw,
            'enter_time': None,
            'goal_time': 0,
            'study_time': 0
        }
        db.users.insert_one(user)
        flash("회원가입이 완료되었습니다.")
        return redirect(url_for("login"))
    
    return render_template("Register.html")


# 로그아웃 라우트
@app.route("/logout")
def logout():
    userid = get_user_from_jwt()
    if userid: # refresh_token 삭제// DB 자체의 필드를 삭제 
        db.users.update_one({"userid": userid}, {"$unset": {"refresh_token": ""}})
    session.clear()  # access_token도 삭제됨
    
    # 클라이언트 쿠키에서 refresh_token 삭제
    response = make_response(redirect(url_for("home")))
    response.delete_cookie("refresh_token")
    return response



# 목표 설정 페이지
@app.route('/goal', methods=["GET"])
def goal():
    userid = get_user_from_jwt()
    if not userid:
        flash("로그인 후 이용해주세요.", "danger")
        return redirect(url_for("login"))
    elif userid == "EXPIRED✍":
        print("Access Token이 만료됨. refresh token으로 재발급합니다.")
        return redirect(url_for("refresh"))
    return render_template("Goal.html")

# 목표 설정 처리 라우트
@app.route('/set_goal', methods=["POST"])
def set_goal():
    userid = get_user_from_jwt()
    if not userid:
        flash("로그인 후 이용해주세요.", "danger")
        return redirect(url_for("login"))
    elif userid == "EXPIRED✍":
        print("Access Token이 만료됨. refresh token으로 재발급합니다.")
        return redirect(url_for("refresh"))
    user_goal_time = request.form.get('weekly_goal')
    sec_user_goal_time = int(user_goal_time) * 3600
    db.users.update_one({'userid': userid}, {'$set': {'goal_time': sec_user_goal_time}})
    return redirect(url_for("mypage"))

# 마이페이지
@app.route('/mypage', methods=["GET"])
def mypage():
    userid = get_user_from_jwt()
    if not userid:
        flash("로그인 후 이용해주세요.", "danger")
        return redirect(url_for("login"))
    elif userid == "EXPIRED✍":
        print("Access Token이 만료됨. refresh token으로 재발급합니다.")
        return redirect(url_for("refresh"))
    now = datetime.now()
    user = db.users.find_one({"userid": userid})
    if not user:
        return redirect(url_for("login"))
    
    user_name = user.get("username")
    enter_time = user.get("enter_time")
    
    # 오늘 공부 시간 계산
    today_seconds = 0
    enter_time_timestamp = None
    if enter_time and enter_time.date() == now.date():
        today_seconds = int((now.replace(tzinfo=None) - enter_time).total_seconds())
        enter_time_timestamp = int(enter_time.timestamp())
    hours = today_seconds // 3600
    minutes = (today_seconds % 3600) // 60
    seconds = today_seconds % 60
    
    # 주간 목표 및 달성률 계산
    goals = user.get("goal_time", 0)
    goal_hour = round(goals // 3600)
    
    study_time = user.get("study_time", 0)
    week_percent = 0 if goals == 0 else round((study_time / goals) * 100, 2)
    
    w_hours = round(study_time // 3600)
    w_minutes = round((study_time % 3600) // 60)
    
    # 사용자의 순위 계산
    users = db.users.find().sort("study_time", -1)
    my_rank = -1
    for i, k in enumerate(users):
        if k["userid"] == userid:
            my_rank = i + 1
            break
    
    return render_template("Mypage.html",
                           username=user_name,
                           today_hours=hours,
                           today_minutes=minutes,
                           today_seconds_html=seconds,
                           weekly_goal=goal_hour,
                           progress_percent=week_percent,
                           week_study_hour=w_hours,
                           week_study_minute=w_minutes,
                           rank=my_rank,
                           enter_time_timestamp=enter_time_timestamp)

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
