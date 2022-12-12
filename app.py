from flask import Flask, jsonify, make_response, session, url_for, request
from flask_restful import Resource, Api, reqparse, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import os
import re
import pymysql.cursors
import bcrypt
import jwt
import datetime

# Api Config
load_dotenv()
app = Flask(__name__)
app.config["BUNDLE_ERRORS"] = True
api = Api(app, prefix="/api/v1")
CORS(app)

# Session config
app.secret_key = os.getenv("APP_SECRET_KEY")
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=5)

# Cache Config
cache = Cache(config={"DEBUG":True, "CACHE_TYPE":"SimpleCache","CACHE_DEFAULT_TIMEOUT":300})
cache.init_app(app)

# Limiter Config
limiter = Limiter(app, key_func=get_remote_address, default_limits=["300 per hour"])



# DB Connection Config
connection = pymysql.connect(host=os.getenv("HOST_DB"),
							 user=os.getenv("USER_DB"),
							 password=os.getenv("PASSWORD_DB"),
							 database=os.getenv("NAME_DB"),
							 cursorclass=pymysql.cursors.DictCursor
							 )

							 
							 
# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    #userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'email profile'},
)							 
		
		
# Starter For Check API Running
@app.route("/", methods=["GET"])
def starter():
	return jsonify(result="API Running!")

	
# Function For Validate Email
def checkEmail(email):
		regex=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
		if re.fullmatch(regex, email):
			return True
		else:
			return False

	
# Function For Send Email	
def sendEmail(target_email):
	# package
	import smtplib, ssl
	from email.mime.text import MIMEText
	from email.mime.multipart import MIMEMultipart

	# Config
	port = 465
	smpt_server="smtp.gmail.com"
	sender_email=os.getenv("EMAIL")
	target_email=target_email
	password=os.getenv("PASSWORD")
	
	# Config Message
	message= MIMEMultipart("alternative")
	message['Subject'] = "Flask Blog"
	message["From"] = f"SLINK<{sender_email}>"
	message['To'] = target_email
	
	# Message
	text = """\
	Subject:
	Flask Blog
	
	
	Test For Send Email Flask Blog
	"""
	
	html = """\
	<h1>Test Flask Send Email Blog</h1>
	<p>This is for test Flask Blog sending email</p>
	"""
	
	part1 = MIMEText(text, 'plain')
	part2 = MIMEText(html, 'html')
	
	message.attach(part1)
	message.attach(part2)
	
	
	# Send
	context = ssl.create_default_context()
	with smtplib.SMTP_SSL(smpt_server, port, context=context) as server:
		server.login(sender_email, password)
		server.sendmail(sender_email, target_email, message.as_string())
		return True			
	
	
#Custom Validator Auth User
def input_username(value):
	if len(value) < 5:
		raise ValueError("Username Min 5 Char!")

	return value
	
def input_password(value):
	if len(value) < 6:
		raise ValueError("Pasaword Min 6 Char!")

	return value

def input_email(value):
	if len(value) == 0:
		raise ValueError('Email Field Empty!')
		
	if checkEmail(value) == False:
		raise ValueError('Email Not Valid!')
		
	return value
		
	

	
#Custom Validator Blog
def input_title(value):
	if len(value) < 5:
		raise ValueError("Title Min 5 Char!")

	return value
		
def input_content(value):
	if len(value) < 20:
		raise ValueError("Content Min 20 char")
		
	return value
	
def input_user_id(value):
	with connection.cursor() as cursor:
		# Check user_id in DB or Not
		sql = "SELECT * FROM users WHERE id=%s"
		cursor.execute(sql, value)
		result = cursor.fetchone()
		if result == None:
			raise ValueError("user_id Not Registered!")
			
	return value
		
#Validator Input Blog
blog_args = reqparse.RequestParser()
blog_args.add_argument("title", type=input_title, location="form", required=True)
blog_args.add_argument("content", type=input_content, location="form", required=True)

# Validator Input Register User
user_register_args = reqparse.RequestParser()
user_register_args.add_argument("username", type=input_username, location="form", required=True)
user_register_args.add_argument("password", type=input_password, location="form", required=True)
user_register_args.add_argument("email", type=input_email, location="form", required=True)


# Validator Input Login User
user_login_args = user_register_args.copy()
user_login_args.remove_argument("email")

# Valdator Input Update Profile User
user_update_profile_args = user_login_args.copy()

# Validator Token
token_args = reqparse.RequestParser()
token_args.add_argument("token", location="headers", required=True, help="User Not Authenticated!")

# Decorator Validate Auth
def validateAuth(function):
	def wrapper(self, *args, **kwargs):
		if session.get('data'):
			kwargs['data'] = dict(session).get("data")
			return function(self, *args, **kwargs)
			
		args_header = token_args.parse_args()	
		if not args_header['token']:
			return make_response(jsonify({"message":"User Not Authenticated!"}), 401)
			
		try:
			data = jwt.decode(args_header['token'], os.getenv("SECRET_KEY"), algorithms=['HS256'])
			kwargs['data'] = data
			return function(self, *args, **kwargs)
		except Exception as e:
			return make_response(jsonify({"message":str(e)}), 401)
			
	return wrapper

	
# Resource Register
class Register(Resource):
	@limiter.limit("5/hour")
	def post(self):
		args = user_register_args.parse_args()
		
		# Check If Username Already Used
		with connection.cursor() as cursor:
			sql="SELECT * FROM users WHERE username = %s"
			value = args["username"]
			cursor.execute(sql, value)
			usernameExist = cursor.fetchone()
			if usernameExist:
				return make_response(jsonify({"message":"Username Already Used!"}),400)
			
			
		# Check If Email Alread Used
		with connection.cursor() as cursor:
			sql="SELECT * FROM users WHERE email = %s"
			value = args["email"]
			cursor.execute(sql, value)
			emailExist = cursor.fetchone()
			if emailExist:
				return make_response(jsonify({"message":"Email Already Used!"}),400)
				
				
		# If Username & Email Not Used
		hash = bcrypt.hashpw(args['password'].encode('utf-8'), bcrypt.gensalt(12))
		with connection.cursor() as cursor:
			# Query Register User
			sql = "INSERT INTO users VALUES(NULL, %s, %s, %s)"
			value = (args['username'], hash, args['email'])
			cursor.execute(sql, value)
			connection.commit()
			sendEmail(args['email'])
			return make_response(jsonify({"result": "User Registered!"}),201)


# Resource Login
class Login(Resource):
	@limiter.limit("10/hour")
	def post(self):
		args = user_login_args.parse_args()
		
		#Check Username
		with connection.cursor() as cursor:
			sql="SELECT * FROM users WHERE username = %s"
			value = args["username"]
			cursor.execute(sql, value)
			usernameExist = cursor.fetchone()
			if not usernameExist:
				return make_response(jsonify({"message":"Wrong Username or Password!"}),400)
				
			# Check Password
			if bcrypt.checkpw(args['password'].encode('utf-8'), usernameExist['password'].encode('utf-8')):
				token = jwt.encode({"user_id": usernameExist['id'], "exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=120)},os.getenv("SECRET_KEY"), algorithm='HS256' )
				return jsonify({"result":"User Login!","token":token})
			else:
				return make_response(jsonify({"message":"Wrong Username or Password!"}), 400)
			
	
	
# Resource Blogs
class Blog(Resource):
	@validateAuth
	@cache.cached(timeout=100)
	@limiter.limit("150/hour")
	def get(self, data=None, id=None):
		if id == None:
			with connection.cursor() as cursor:
				# Query Get Blogs From DB
				sql = "SELECT * FROM blogs"
				cursor.execute(sql)
				result = cursor.fetchall()
				return jsonify({"result":result, "data": data})
		
		
		with connection.cursor() as cursor:
			# Query Get Blog By Id From DB
			sql = "SELECT * FROM blogs WHERE id=%s"
			value = id
			cursor.execute(sql,value)
			result = cursor.fetchone()
			if result == None:
				return make_response(jsonify({"message":"Blog Not Found"}), 404)
				
			return jsonify({"result":result})
		
		
	@validateAuth
	@limiter.limit("40/hour")
	def post(self, data=None):
		args = blog_args.parse_args()
		with connection.cursor() as cursor:
			# Query Create Blog
			sql = "INSERT INTO blogs VALUES(NULL, %s, %s, %s)"
			value = (args['title'], args['content'], data["user_id"])
			cursor.execute(sql, value)
			connection.commit()
			return make_response(jsonify({"result": "Blog Created!"}),201)
			
			
	@validateAuth
	@limiter.limit("50/hour")	
	def patch(self,data=None, id=None):
		args = blog_args.parse_args()
		if id == None:
			return make_response(jsonify({"message":"Blog Not Found"}), 404) 

		# Check If Blog Exist and Did Authenticated User Have Access CRUD This Blog
		with connection.cursor() as cursor:
			# Query Check Blog Exist
			sql = "SELECT user_id FROM blogs WHERE id=%s"
			cursor.execute(sql, id)
			blogExist = cursor.fetchone()
			
			if not blogExist:
				return make_response(jsonify({"message":"Blog Not Found"}), 404)
			
			# Check Authorization
			if blogExist['user_id'] != data['user_id']:
				return make_response(jsonify({"message": "Access Denied!"}),403)
		
		with connection.cursor() as cursor:
			# Query Create Blog
			sql = "UPDATE blogs SET title = %s, content=%s, user_id=%s WHERE id=%s"
			value = (args['title'], args['content'], data['user_id'], id)
			cursor.execute(sql, value)
			connection.commit()
			return make_response(jsonify({"result": "Blog Updated!"}),200)
	

	@validateAuth
	@limiter.limit("60/hour")
	def delete(self,data=None,id=None):
		if id == None:
			return make_response(jsonify({"message":"Blog Not Found"}), 404) 
			
		# Check If Blog Exist and Did Authenticated User Have Access CRUD This Blog
		with connection.cursor() as cursor:
			# Query Create Blog
			sql = "SELECT user_id FROM blogs WHERE id=%s"
			cursor.execute(sql, id)
			blogExist = cursor.fetchone()
			
			if not blogExist:
				return make_response(jsonify({"message":"Blog Not Found"}), 404)
				
			if blogExist['user_id'] != data['user_id']:
				return make_response(jsonify({"message": "Access Denied!"}),403)
				
		with connection.cursor() as cursor:
			# Query Create Blog
			sql = "DELETE FROM blogs WHERE id=%s"
			cursor.execute(sql, id)
			connection.commit()
			return make_response(jsonify({"result": "Blog Deleted!"}),200)

	

class Google(Resource):
	def get(self):
		google = oauth.create_client('google')  # create the google oauth client
		redirect_uri = url_for('google_callback', _external=True)
		return google.authorize_redirect(redirect_uri)
		
		
class GoogleCallback(Resource):
	def get(self):
		google = oauth.create_client('google')  # create the google oauth client
		token = google.authorize_access_token()  # Access token from google (needed to get user info)
		resp = google.get('userinfo', token=token)  # userinfo contains stuff u specificed in the scrope
		user_info = resp.json()
		#user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
		
		# Here you use the profile/user data that you got and query your database find/register the user
		with connection.cursor() as cursor:
			sql="SELECT * FROM users WHERE email = %s"
			cursor.execute(sql, user_info['email'])
			emailExist = cursor.fetchone()
			
			if emailExist:
				# set ur own data in the session not the profile from google
				session['data'] = {"user_id":emailExist["id"], "exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=120)}
				session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
				return jsonify({"result":"User Login!"})
				
				
		hash = bcrypt.hashpw(str(user_info['id']).encode('utf-8'), bcrypt.gensalt(14))
		with connection.cursor() as cursor:
			# Create User Also Give Default Username & Password(Change Later After User Login)
			sql="INSERT INTO users VALUES(NULL, %s, %s, %s)"
			value = (user_info['name']+user_info['email'], hash, user_info['email'])
			cursor.execute(sql, value)
			connection.commit()
			
		
		with connection.cursor() as cursor:
			sql="SELECT * FROM users WHERE email = %s"
			cursor.execute(sql, user_info['email'])
			newUser = cursor.fetchone()
			exp = datetime.datetime.utcnow()+datetime.timedelta(minutes=120)
			session['data'] = {"user_id":newUser["id"], "exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=120)}
			session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
			return jsonify({"result":"User Login!"})
		

class Profile(Resource):
	@validateAuth
	def patch(self, data=None):
		args = user_update_profile_args.parse_args()
		# Check If Username Already Used
		with connection.cursor() as cursor:
			sql="SELECT * FROM users WHERE username = %s"
			value = args["username"]
			cursor.execute(sql, value)
			usernameExist = cursor.fetchone()
			if usernameExist:
				return make_response(jsonify({"message":"Username Already Used!"}),400)

		
		hash = bcrypt.hashpw(args['password'].encode('utf-8'), bcrypt.gensalt(14))
		with connection.cursor() as cursor:
			sql="UPDATE users SET username=%s, password=%s WHERE id = %s"
			value=(args['username'], hash, data['user_id'])
			cursor.execute(sql, value)
			connection.commit()
			return jsonify({"result":"Profile Updated!"})

	
class Logout(Resource):
	@validateAuth
	def get(self, data=None):
		for key in list(session.keys()):
			session.pop(key)
			
		return jsonify({"result":"User Logout!"})
		

		
		
	
		
api.add_resource(Blog, "/blogs","/blogs/<id>", methods=["GET","POST","PATCH","DELETE"])
api.add_resource(Register, "/register", methods=["POST"])
api.add_resource(Login, "/login", methods=["POST"])
api.add_resource(Google, "/google", methods=["GET"])
api.add_resource(GoogleCallback, "/google/callback", methods=['GET'], endpoint="google_callback")
api.add_resource(Profile, "/profile", methods=["PATCH"])
api.add_resource(Logout, "/logout", methods=["GET"])
		
		
if __name__ == "__main__":
	app.run()