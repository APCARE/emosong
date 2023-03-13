import os
import requests
from flask import Flask, request, jsonify, make_response, redirect, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
import uuid
from sqlalchemy import ForeignKey, false
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from functools import wraps
import json
import jwt
from serializer import Serializer
from urllib.parse import quote  
from flask_restful import reqparse, abort, Api, Resource
import re
# from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
# from flask_jwt_extended import JWTManager
from sqlalchemy.orm import Session
import logging
from logging import FileHandler 
import uuid
import capture as cap
from multiprocessing import Process

app = Flask(__name__,static_url_path='',static_folder='./static')
app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:%s@localhost/flask' % quote('root')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
api = Api(app)

logoO = '04469b2ae1b159017ae110bc9235$vJdWdrveiXVgDzM3$000062:652ahscb16c645e3688c1fbf24b32a1bcb2a2a3cd6'
xyz = '04469b2ae1b159cb16c645e3688c1fbf24b32a1bcb2a2a3cd6017ae110bc9235$vJdWdrveiXVgDzM3$000062:652ahs'
passw = 'pbkdf2:sha256:260000$3MzDgVXievrdWdJv$5329cb011ea7106dc3a2a2bcb1a23b42fbf1c8863e546c61bc951b1ea2b96440'
udd = 'XXX'

app.config["JWT_COOKIE_SECURE"] = False
# app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_CSRF_METHODS"] = ["POST"]
app.config["JWT_SECRET_KEY"] = "004f2af45d3a4e161a7dd2d17fdae47f"  # Change this in your code!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes = 5)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(minutes = 10)

# jwt = JWTManager(app)

db = SQLAlchemy(app)



# db models
class Users(db.Model, Serializer):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    date_joined = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime)
   
    # category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    # category = db.relationship('Category', backref=db.backref('posts', lazy='dynamic'))

    def __init__(self, name, email, password, date_joined = None, last_login = None):
        self.name = name
        self.email = email
        self.password = password
        self.date_joined = date_joined
        # if date_joined is None:
        #     self.date_joined = datetime.datetime.utcnow()
        self.last_login = last_login


    def serialize(self):
        d = Serializer.serialize(self)
        return d


    def __str__(self):
        return self.name

 


db.create_all()

# global functions

def makeJsonResponse(data, msg, code):
    if msg :
        data["error_message"] =  msg

    data["status"] = code
    return data, code

def passwordValidation(password,confirm_password):
    if not password or not confirm_password:
        return False,'Password or Confirm Password is not given. Please try again.', 406 
    if not confirm_password == password:
        return False, 'Password and Confirm Password mismatch. Please try again.', 406
     

    SpecialSym =['$', '@', '#', '%', '!', '^', '&', '*']

    if len(password) < 8:
        return False, 'Password length should be at least 8', 406
        
          
    if len(password) > 20:
         return False, 'Password length should be not be greater than 20', 406
          
    if not any(char.isdigit() for char in password):
        return False, 'Password should have at least one numeral', 406
        
          
    if not any(char.isupper() for char in password):
        return False, 'Password should have at least one uppercase letter', 406
        
          
    if not any(char.islower() for char in password):
        return False, 'Password should have at least one lowercase letter', 406
        
          
    if not any(char in SpecialSym for char in password):
        return False, 'Password should have at least one of the symbols $@#', 406
        
    return True,'',''
    

# end points
class successOne(Resource):
    def get(self, user_type):
        global udd
        ud = uuid.uuid4().hex  
        udd = ud           
        if user_type == passw:
            # return make_response(render_template('admin.html'))
            return make_response(redirect(f"/admin/{ud}"))
        elif user_type == xyz:
            # return make_response(redirect(f'/loged_in_successful/{ud}'))
            return make_response(redirect(f'/emomusic/{ud}'))
        else:
            return make_response(render_template('error.html'))
        # return resp
        
class success(Resource):
    def get(self, ud):
        global logoO
        if ud == logoO: 
            logoO = uuid.uuid4().hex  + uuid.uuid4().hex
            # udd = "xxx"
            return make_response(render_template('success.html'))
        else: 
            return make_response(render_template('error.html'))

class admin(Resource):
    def get(self, ud):
        global udd
        if ud == udd: 
            udd = "xxx"
            return make_response(render_template('admin.html'))
        else: 
            return make_response(render_template('error.html'))



class emomusic2(Resource):
    def get(self, ud):
        global udd
        if ud == udd: 
            udd = "xxx"
            return make_response(render_template('main.html'))
        else: 
            return make_response(render_template('error.html'))

# class emomusic(Resource):
#     def get(self):
#         return make_response(render_template('main.html'))

class get_emotion(Resource):   
    def get(self):
        try:
            emotion = cap.getEmotion()
            return makeJsonResponse({"data": emotion}, '', 200)
        except :
            return makeJsonResponse({}, 'Something Went Wrong Pleae Try Again Later', 406)


class signUpPage(Resource):
    def get(self):
        return make_response(render_template('login.html'))

class signUp(Resource):
    # @api_key_validation_checker
    def post(self):
        # creates a dictionary of the form data
        data = request.get_json()
        # app.logger.info(f'SignUp request with new user data: %s'% data)
        # gets name, email and password
        name = data.get('name','')
        email = data.get('email','')
        password = data.get('password','')
        confirm_password = data.get('confirm_password','')
        
        # check for password validation
        password_valid, pwd_error_message, pwd_error_code = passwordValidation(password,confirm_password)
        if not password_valid:
            return makeJsonResponse({}, pwd_error_message, pwd_error_code)

        # check email validation 
        if not re.fullmatch( r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email):
            return makeJsonResponse({}, 'Please enter a valid email address.', 406)
        # check for email already exist
        exist_email = Users.query.filter_by(email = email).first()

        if exist_email:
            return makeJsonResponse({}, 'Email already exists. Please change email.', 406)

        date_joined = datetime.datetime.utcnow()
        last_login = None
        # checking for existing user
        # user = Users.query.filter_by(username = username).first()
        # if not user:
            # database ORM object
        
        # app.logger.info(f'first_name: %s, last_name: %s, email: %s, username: %s, password: %s, mobile_number: %s, is_superuser: %s, is_staff: %s, user_type: %s, get_pass_number: %s, device_mac_add: %s, is_active: %s, date_joined: %s, last_login: %s' % (first_name, last_name, email, username, password, mobile_number, is_superuser, is_staff, user_type, get_pass_number, device_mac_add, is_active, date_joined, last_login))
        try:
            user = Users(
                name = name,
                email = email,
                password = generate_password_hash(password),
                date_joined = datetime.datetime.utcnow(),
                last_login = last_login
            )
            # insert user
            db.session.add(user)
            db.session.commit()
            
            userdata = Users.query.filter_by(email = email).first()
            datass = Users.serialize(userdata)
            # app.logger.info(f'Newly registered user data: %s'% datass)
            # remove secret datas from response
            list(map(datass.pop, ["password"]))
            return makeJsonResponse(datass, 'tt', 201)
        except:
            # returns 202 if user already exists
            return makeJsonResponse({}, 'User Registration Failed! Please try again.', 400)
    
class userDetails(Resource):
    def get(self):
        # app.logger.info(f'User details requested By userid: %s'% get_jwt().get("userid"))
        userdata = Users.query.all()
        user_data = ''
        if userdata:
            user_data = Users.serialize_list(userdata)
            print(user_data)
            list(map(lambda user: user.pop("password"), user_data))
            # app.logger.info(f'Response User Details : %s'% user_data)
            return makeJsonResponse({"data": user_data}, '', 200)
        else:
            # app.logger.info('Invalid username, User not exist in the database')
            return makeJsonResponse({}, 'Something Went Wrong Pleae Try Again Later', 406)


class logIn(Resource):
    # @api_key_validation_checker
    def post(self):
        auth = request.get_json()
        if auth.get('email') == "admin@admin.com" and  check_password_hash(passw, auth.get('password')):
            return makeJsonResponse({'user': passw}, '', 201)

        # app.logger.info(f'Login requested for: %s'% auth.get('username'))
        if not auth or not auth.get('email') or not auth.get('password'):
            # returns 401 if any name or / and password is missing
            return makeJsonResponse({}, 'Please Enter a valid username and password!', 406)
    
        user = Users.query.filter_by(email = auth.get('email')).first()
    
        if not user:
            # returns 401 if user does not exist
            return makeJsonResponse({}, 'User does not exist.', 401)

        
        # if user.password == auth.get('password'):
        if check_password_hash(user.password, auth.get('password')):
            # generates the JWT Token
            additional_claims = {"userid": user.id}
            # app.logger.info(f'Successfully modified the last_login details in "User" table for userid: %s' % user.id)
            user.last_login = datetime.datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            return makeJsonResponse({'user': xyz}, '', 201)
   
            # return resp

        else:
            # returns 403 if password is wrong
            return makeJsonResponse({}, 'Please enter valid Password!', 403)

class deleteUser(Resource):
    def post(self):
        auth = request.get_json()
        user = Users.query.filter_by(email = auth.get('email')).first()
        if not user:
            return makeJsonResponse({}, 'User does not exist. Please refresh the page.', 401)
        else:
            db.session.delete(user)
            db.session.commit()
            return makeJsonResponse({}, 'User Successfully Deleted', 201)

class logOut(Resource):
    def post(self):
        global logoO
        logoO = uuid.uuid4().hex  
        # udd = ud   
        return makeJsonResponse({'user': logoO}, '', 201)        




api.add_resource(signUpPage, '/signup')
api.add_resource(successOne, '/loged_in/<user_type>')
api.add_resource(success, '/loged_out_successful/<ud>')
api.add_resource(admin, '/admin/<ud>')
api.add_resource(userDetails, '/api/v1/get_all_users')
api.add_resource(deleteUser, '/api/v1/delete_user')
api.add_resource(logIn, '/api/v1/login')
api.add_resource(signUp, '/api/v1/signup')
api.add_resource(logOut, '/api/v1/logout')
# api.add_resource(emomusic, '/emomusic')
api.add_resource(emomusic2, '/emomusic/<ud>')
api.add_resource(get_emotion, '/api/v1/get_emotion')



if  __name__ == '__main__': 
    todate = datetime.datetime.today().strftime("%d_%m_%Y")
    month = datetime.datetime.today().strftime("%B")
    if not os.path.exists(f'./logs/%s' % month):
        os.mkdir(f'./logs/%s' % month)
    
    app.run(debug=True)
