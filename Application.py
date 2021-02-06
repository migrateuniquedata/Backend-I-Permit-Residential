from random import randint
import re
from flask import Flask, request, jsonify
from pymongo import MongoClient
from time import strftime
import requests
import base64
from flask_pymongo import PyMongo
from pyfcm import FCMNotification

from pytz import timezone
from time import strftime
import json
# import datetime as dt
# from flask_cors import CORS, cross_origin
# from flask_mail import Mail, Message
# import pymongo
# import json
# import os
# from werkzeug.utils import secure_filename
import urllib.request
import urllib.parse
# from datetime import datetime
import datetime

# import url
app = Flask(__name__)

# client = MongoClient('54.173.165.201:6909')

# app.config['MONGO_DBNAME'] = 'ipermit'
# app.config['MONGO_URI'] = 'mongodb://54.173.165.201:6909/ipermit'
app.config['MONGO_URI'] = 'mongodb://54.198.58.188:6909/ires'
mongo = PyMongo(app)


# app.config['JWT_SECRET_KEY'] = 'permit'
# app.config['MONGO_USERNAME'] = 'root'
# app.config['MONGO_PASSWORD'] = 'pass123'
# app.config['MONGO_AUTH_SOURCE'] = 'admin'


##################################### company signup############################################

@app.route('/i_res/community_signup', methods=['POST'])
def community_signup():
    coll = mongo.db.community_list
    try:
        community_name = str(request.json['community_name'])
        email_id = request.json['email_id']
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        current_dt = now_asia.strftime('%Y/%m/%d %H:%M')

        company = community_name[0:3]
        company = company.upper()
        numeric = randint(100, 999)
        community_id = ''.join(company + str(numeric))

        for user in coll.find():
            if user['email_id'] == email_id:
                return jsonify(({'status': 0, 'message': 'Email is already there'}))
        output = []
        coll.insert(
            {'community_id': community_id, 'community_name': community_name, 'created_time': current_dt,
             'email_id': email_id,
             })
        output.append(
            {'community_id': community_id, 'community_name': community_name, 'created_time': current_dt,
             'email_id': email_id,
             })
        return jsonify({'status': 1, 'message': 'Community data uploaded successfully', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e), 'result': 'Unable to register. Please try again'})


#######################################company list ##########################################################

@app.route('/i_res/get_community_list', methods=['POST', 'GET'])
def get_community_list():
    # db = client.ipermit
    coll = mongo.db.community_list
    output = []
    for i in coll.find():
        temp = {}
        temp['community_id'] = i['community_id']
        temp['community_name'] = i['community_name']
        temp['email_id'] = i['email_id']
        temp['created_time'] = i['created_time']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Community List', 'result': output})


#############################################company id validation ##################################################

@app.route('/i_res/community_id_validate', methods=['POST'])
def community_id_validate():
    coll = mongo.db.community_list
    try:
        community_id = request.json['community_id']
        output = []
        for li in coll.find({"community_id": {'$regex': re.compile(community_id, re.IGNORECASE)}}):
            output.append(
                {'community_name': li['community_name'], 'community_id': li['community_id'],
                 })
            return jsonify({'status': 1, 'message': 'Authorization Successfull', 'result': output})

        return jsonify({'status': 0, 'message': 'Authorization Failed'})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


#######################################################sign up##################################################################

@app.route('/i_res/security_signup', methods=['POST'])
def security_signup():
    # db = client.ipermit
    coll = mongo.db.security_users
    try:
        community_id = request.json['community_id']
        language = request.json['language']
        try:
            language_type = request.json['language_type']
        except:
            language_type = ''
        try:
            type = request.json['type']
        except:
            type = ''
        name = str(request.json['name'])
        email_id = request.json['email_id']
        mobile_number = request.json['mobile_number']
        # otp=request.json['otp']
        flat_number = request.json['flat_number']
        block_number = request.json['block_number']
        password = request.json['password']
        confirm_password = request.json['confirm_password']
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        current_dt = now_asia.strftime('%Y/%m/%d %H:%M')

        if password != confirm_password:
            return jsonify({'status': 0, 'message': "Passwords do not match. try again"})
        for user in coll.find():
            if user['mobile_number'] == mobile_number:
                return jsonify(({'status': 0, 'message': 'Mobile number is already register .Please Sign In '}))
        for user in coll.find():
            if user['email_id'] == email_id:
                return jsonify(({'status': 0, 'message': 'Email is already register .Please check once'}))
        for user in coll.find():
            if user['flat_number'] == flat_number:
                return jsonify(({'status': 0, 'message': 'Flat number is already there .Please check once'}))
        if re.search('[0-9]', name) is not None:
            return jsonify({'status': 0, 'message': "Please Enter valid Name"})
        elif re.search('[+!@#$%^&*_-]', name) is not None:
            return jsonify({'status': 0, 'message': 'Please Enter valid Name'})

        otp = randint(1000, 9999)
        sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number,
                "Your OTP for IPERMIT RESIDENTIAL is " + str(otp))
        try:
            device_token = request.json['device_token']
        except KeyError or ValueError:
            device_token = ''

            # url = "http://weberleads.in/http-tokenkeyapi.php?authentic-key=3335636e725f746563686e6f6c6f6769656173323732156629" \
            #       "&senderid=cnrweg&route=2&number=" + mobile_number + "&message=Your OTP is" + str(otp)
            # f = requests.get(url)
        sec_id_list = [i['sec_id'] for i in coll.find()]
        if len(sec_id_list) is 0:
            sec_id = 1
        else:
            sec_id = int(sec_id_list[-1]) + 1

        if re.match(pattern=r'(^[0-9]{10}$)', string=mobile_number):  # check for mobilenumber properly
            # if re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,15}$", password):  # check for password properly
            if re.match(r'[A-Za-z0-9@#$%^&+=]{6,12}', password):
                output = []

                coll.insert(
                    {'name': name, 'otp': str(otp), 'community_id': community_id, 'device_token': device_token,
                     'sec_id': sec_id,
                     'mobile_number': mobile_number, 'email_id': email_id, 'language': language, 'verify_status': False,
                     'flat_number': flat_number, 'created_time': current_dt, 'language_type': language_type,
                     'type': type, 'block_number': block_number,
                     'password': password})
                output.append(
                    {'sec_id': sec_id, 'name': name, 'otp': str(otp), 'community_id': community_id,
                     'device_token': device_token,
                     'mobile_number': mobile_number, 'email_id': email_id, 'language': language, 'verify_status': False,
                     'flat_number': flat_number, 'created_time': current_dt, 'language_type': language_type,
                     'type': type, 'block_number': block_number,
                     'password': password})
                return jsonify({'status': 1, 'message': ' Security User Sign Up successfully', 'result': output})
            else:
                return jsonify({'status': 0, 'message': 'Please Enter Strong Password'})
        else:
            return jsonify({'status': 0, 'message': 'Invalid mobile number'})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e), 'result': 'Unable to register. Please try again'})


@app.route('/i_res/resident_signup', methods=['POST'])
def resident_signup():
    # db = client.ipermit
    coll = mongo.db.resident_users
    try:
        community_id = request.json['community_id']
        language = request.json['language']
        try:
            language_type = request.json['language_type']
        except:
            language_type = ''
        try:
            type = request.json['type']
        except:
            type = ''

        name = str(request.json['name'])
        email_id = request.json['email_id']
        mobile_number = request.json['mobile_number']
        # otp=request.json['otp']
        flat_number = request.json['flat_number']
        block_number = request.json['block_number']
        # emp_code=request.json['emp_code']
        password = request.json['password']
        confirm_password = request.json['confirm_password']
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        current_dt = now_asia.strftime('%Y/%m/%d %H:%M')

        if password != confirm_password:
            return jsonify({'status': 0, 'message': "Passwords do not match. try again"})
        for user in coll.find():
            if user['mobile_number'] == mobile_number:
                return jsonify(({'status': 0, 'message': 'Mobile number is already register .Please Sign In '}))
        for user in coll.find():
            if user['email_id'] == email_id:
                return jsonify(({'status': 0, 'message': 'Email is already register .Please check once '}))
        for user in coll.find():
            if user['flat_number'] == flat_number:
                return jsonify(({'status': 0, 'message': 'Resident code is already register .Please check once '}))
        if re.search('[0-9]', name) is not None:
            return jsonify({'status': 0, 'message': "Please Enter valid Name"})
        elif re.search('[+!@#$%^&*_-]', name) is not None:
            return jsonify({'status': 0, 'message': 'Please Enter valid Name'})
        otp = randint(1000, 9999)
        sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number,
                "Your OTP for IPERMIT RESIDENTIAL is " + str(otp))
        try:
            device_token = request.json['device_token']
        except KeyError or ValueError:
            device_token = ''

            # url = "http://weberleads.in/http-tokenkeyapi.php?authentic-key=3335636e725f746563686e6f6c6f6769656173323732156629" \
            #       "&senderid=cnrweg&route=2&number=" + mobile_number + "&message=Your OTP is" + str(otp)
            # f = requests.get(url)
        e_id_list = [i['e_id'] for i in coll.find()]
        if len(e_id_list) is 0:
            e_id = 1
        else:
            e_id = int(e_id_list[-1]) + 1

        if re.match(pattern=r'(^[0-9]{10}$)', string=mobile_number):  # check for mobilenumber properly
            # if re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,15}$", password):  # check for password properly
            if re.match(r'[A-Za-z0-9@#$%^&+=]{6,12}', password):
                output = []
                coll.insert(
                    {'name': name, 'community_id': community_id, 'language_type': language_type, 'type': type,
                     'e_id': e_id,
                     'mobile_number': mobile_number, 'email_id': email_id, 'language': language,
                     'device_token': device_token,
                     'flat_number': flat_number, 'created_time': current_dt, 'otp': str(otp), 'verify_status': False,
                     'password': password, 'block_number': block_number})
                output.append(
                    {'e_id': e_id, 'name': name, 'community_id': community_id, 'otp': str(otp),
                     'device_token': device_token,
                     'mobile_number': mobile_number, 'email_id': email_id, 'language': language, 'verify_status': False,
                     'flat_number': flat_number, 'created_time': current_dt, 'block_number': block_number,
                     'password': password})
                return jsonify({'status': 1, 'message': ' Resident Sign Up successfully', 'result': output})
            else:
                return jsonify({'status': 0, 'message': 'Please Enter Strong Password'})
        else:
            return jsonify({'status': 0, 'message': 'Invalid mobile number'})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e), 'result': 'Unable to register. Please try again'})


#################################### verify-otp #############################################

@app.route('/i_res/security_verify_otp', methods=['POST'])
def security_verify_otp():
    try:
        # db = client.ipermit
        coll = mongo.db.security_users
        otp = str(request.json['otp'])
        mobile_number = str(request.json['mobile_number'])
        output = []
        details = coll.find({'mobile_number': str(mobile_number), 'otp': str(otp)})
        for data in details:
            if data['otp'] == otp:
                coll.update({'mobile_number': mobile_number}, {"$set": {'verify_status': True}})
                output.append({'sec_id': data['sec_id'], 'name': data['name'], 'email_id': data['email_id'],
                               'password': data['password'], 'mobile_number': data['mobile_number'],
                               'otp': data['otp'], 'Verified': 1, 'created_time': data['created_time']})
        finaloutput = {}
        if len(output) != 0:
            finaloutput['status'] = 1
            finaloutput['message'] = 'Otp verified successfully'
            finaloutput['result'] = output
        else:
            finaloutput['status'] = 0
            finaloutput['message'] = 'Invalid OTP. Please check and try again'
            # finaloutput['result'] = []
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/resident_verify_otp', methods=['POST'])
def resident_verify_otp():
    try:
        coll = mongo.db.resident_users
        otp = str(request.json['otp'])
        mobile_number = str(request.json['mobile_number'])
        output = []
        details = coll.find({'mobile_number': str(mobile_number), 'otp': str(otp)})
        for data in details:
            if data['otp'] == otp:
                coll.update({'mobile_number': mobile_number}, {"$set": {'verify_status': True}})
                output.append({'e_id': data['e_id'], 'name': data['name'], 'email_id': data['email_id'],
                               'password': data['password'], 'mobile_number': data['mobile_number'],
                               'otp': data['otp'], 'Verified': 1, 'created_time': data['created_time']})
        finaloutput = {}
        if len(output) != 0:
            finaloutput['status'] = 1
            finaloutput['message'] = 'Otp verified successfully'
            finaloutput['result'] = output
        else:
            finaloutput['status'] = 0
            finaloutput['message'] = 'Invalid OTP. Please check and try again'
            # finaloutput['result'] = []
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


################################### send or resend-otp ##############################################

@app.route('/i_res/security_send_otp', methods=['POST'])
def security_send_otp():
    try:
        coll = mongo.db.security_users
        mobile_number = str(request.json['mobile_number'])
        output = []
        res = list(coll.find({'mobile_number': mobile_number}))
        if res != 0:
            otp = randint(1000, 9999)
            sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number,
                    "Your OTP for IPERMIT RESIDENTIAL is " + str(otp))
            coll.update({'mobile_number': mobile_number}, {'$set': {'otp': str(otp)}})
            output.append({'mobile_number': mobile_number, 'otp': str(otp)})
            return jsonify({'status': 1, 'message': 'OTP generated successfully', 'result': output})
        else:
            return jsonify({'status': 0, 'message': 'Please enter valid mobile number'})

    except Exception as e:
        return jsonify({"status": 0, "message": str(e)})


@app.route('/i_res/resident_send_otp', methods=['POST'])
def resident_send_otp():
    try:
        coll = mongo.db.resident_users
        mobile_number = str(request.json['mobile_number'])
        output = []
        res = list(coll.find({'mobile_number': mobile_number}))
        if res != 0:
            otp = randint(1000, 9999)
            sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number,
                    "Your OTP for IPERMIT RESIDENTIAL is " + str(otp))
            coll.update({'mobile_number': mobile_number}, {'$set': {'otp': str(otp)}})
            output.append({'mobile_number': mobile_number, 'otp': str(otp)})
            return jsonify({'status': 1, 'message': 'OTP generated successfully', 'result': output})
        else:
            return jsonify({'status': 0, 'message': 'Please enter a valid mobile number'})

    except Exception as e:
        return jsonify({"status": 0, "message": str(e)})


#######################################################################################################################

@app.route('/i_res/sendSMS', methods=['POST'])
def sendSMS(apikey, numbers, message):
    data = urllib.parse.urlencode({'apikey': apikey, 'numbers': numbers,
                                   'message': message})
    data = data.encode('utf-8')
    request = urllib.request.Request("https://api.textlocal.in/send/?")
    f = urllib.request.urlopen(request, data)
    fr = f.read()
    return (fr)


################################################  login #####################################################################

@app.route('/i_res/login', methods=['POST'])
def login():
    # db = client.ipermit
    coll = mongo.db.security_users
    username = request.json['username']
    password = request.json['password']
    community_id = request.json['community_id']
    try:
        language = request.json['language']
    except:
        language = ''
    try:
        language_type = request.json['language_type']
    except:
        language_type = ''
    try:
        type = request.json['type']
    except:
        type = ''
    try:
        device_token = request.json['device_token']
    except:
        device_token = ''
    try:
        # access_token = create_access_token(identity=username)
        # check_pwd=bcrypt.check_password_hash(password)
        # print(check_pwd)
        details = coll.find({'mobile_number': username, 'password': password, 'community_id': community_id})
        # info = coll.find({'email_id': username, 'password': password})
        output = []
        for data in details:

            try:
                user_pic = data['user_pic']
            except KeyError or ValueError:
                user_pic = "None"
            coll.update({'mobile_number': username}, {
                '$set': {'language': language, 'language_type': language_type, 'type': type,
                         'device_token': device_token}})
            output.append({'sec_id': data['sec_id'], 'name': data['name'], 'email_id': data['email_id'],
                           'mobile_number': data['mobile_number'], 'language': language, 'language_type': language_type,
                           'type': type, 'device_token': device_token,
                           'created_time': data['created_time'], 'user_pic': user_pic,
                           'community_id': data['community_id']})
        # for i in info:
        #     try:
        #         user_pic = i['user_pic']
        #     except KeyError or ValueError:
        #         user_pic = "None"
        #     coll.update({'email_id': username}, {'$set': {'language': language,'language_type':language_type,'type':type,'device_token':device_token}})
        #     output.append({'sec_id': i['sec_id'], 'name': i['name'], 'email_id': i['email_id'],'device_token':device_token,'verify_status':i['verify_status'],
        #                    'mobile_number': i['mobile_number'],'language': language,'language_type':language_type,'type':type,
        #                    'created_time': i['created_time'], 'user_pic': user_pic,'company_id':i['company_id']})
        finaloutput = {}
        if len(output) != 0:
            finaloutput['status'] = 1
            finaloutput['login_status'] = 1
            finaloutput['message'] = 'login Successful'
            finaloutput['result'] = output
            # finaloutput['token'] = access_token
        else:
            finaloutput['status'] = 0
            finaloutput['login_status'] = 0
            finaloutput['message'] = 'Invalid Credentials. Please check and try again'
            finaloutput['result'] = []
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'result': str(e), 'message': 'Unable to login, Please try again'})


@app.route('/i_res/resident_login', methods=['POST'])
def resident_login():
    # db = client.ipermit
    coll = mongo.db.resident_users
    username = request.json['username']
    password = request.json['password']
    community_id = request.json['community_id']
    try:
        language = request.json['language']
    except:
        language = ''
    try:
        language_type = request.json['language_type']
    except:
        language_type = ''
    try:
        type = request.json['type']
    except:
        type = ''
    try:
        device_token = request.json['device_token']
    except:
        device_token = ''
    try:
        # access_token = create_access_token(identity=username)
        # check_pwd=bcrypt.check_password_hash(password)
        # print(check_pwd)
        details = coll.find({'mobile_number': username, 'password': password, 'community_id': community_id})
        # info = coll.find({'email_id': username, 'password': password})
        output = []
        for data in details:
            try:
                user_pic = data['user_pic']
            except KeyError or ValueError:
                user_pic = "None"
            coll.update({'mobile_number': username}, {
                '$set': {'language': language, 'language_type': language_type, 'type': type,
                         'device_token': device_token}})
            output.append({'e_id': data['e_id'], 'name': data['name'], 'email_id': data['email_id'],
                           'verify_status': data['verify_status'],
                           'mobile_number': data['mobile_number'], 'language': language, 'language_type': language_type,
                           'type': type, 'device_token': device_token,
                           'created_time': data['created_time'], 'user_pic': user_pic,
                           'community_id': data['community_id']})
        # for i in info:
        #     try:
        #         user_pic = i['user_pic']
        #     except KeyError or ValueError:
        #         user_pic = "None"
        #     coll.update({'email_id': username}, {'$set': {'language': language,'language_type':language_type,'type':type,'device_token':device_token}})
        #     output.append({'e_id': i['e_id'], 'name': i['name'], 'email_id': i['email_id'],
        #                    'mobile_number': i['mobile_number'],'language':language,'language_type':language_type,'type':type,'device_token':device_token,
        #                    'created_time': i['created_time'], 'user_pic': user_pic,'company_id':i['company_id']})
        finaloutput = {}
        if len(output) != 0:
            finaloutput['status'] = 1
            finaloutput['login_status'] = 1
            finaloutput['message'] = 'login Successful'
            finaloutput['result'] = output
            # finaloutput['token'] = access_token
        else:
            finaloutput['status'] = 0
            finaloutput['login_status'] = 0
            finaloutput['message'] = 'Invalid Credentials. Please check and try again'
            finaloutput['result'] = []
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'result': str(e), 'message': 'Unable to login, Please try again'})


####################################get security profile details ############################################

@app.route('/i_res/get_security_profile_details', methods=['POST', 'GET'])
def get_security_profile_details():
    # db = client.ipermit
    coll = mongo.db.security_users
    output = []
    sec_id = request.json['sec_id']
    for data in coll.find({'sec_id': sec_id}):
        temp = {}
        temp['name'] = data['name']
        temp['community_id'] = data['community_id']

        temp['flat_number'] = data['flat_number']
        temp['block_number'] = data['block_number']
        temp['language'] = data['language']
        temp['language_type'] = data['language_type']
        # if 'department' not in data.keys():
        #     temp['department'] = ""
        # else:
        #     temp['department']=data['department']
        if 'user_pic' not in data.keys():
            temp['user_pic'] = ""
        else:
            temp['user_pic'] = data['user_pic']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Get Security profile details', 'result': output})


###################################### forgot password #############################################################
@app.route('/i_res/security_forgot_password', methods=['POST'])
def security_forgot_password():
    try:
        coll = mongo.db.security_users
        value = request.json['value']
        for data in coll.find():
            mobile_number = data['mobile_number']
            # email = i['email_id']
            if mobile_number == value:
                otp = randint(1000, 9999)
                sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number,
                        "Your OTP for IPERMIT RESIDENTIAL is " + str(otp))
                coll.find_one_and_update({'mobile_number': mobile_number}, {'$set': {'otp': str(otp)}})
                return jsonify({"status": 1, "message": "OTP generated successfully", "otp": str(otp)})
            # if email == value:
            #     otp = randint(1000, 9999)
            #     sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number, otp)
            #     coll.find_one_and_update({'email_id': email}, {'$set': {'otp': str(otp)}})
            #     return jsonify({"status": 1, "message": "OTP generated successfully", "otp": str(otp)})
        else:
            return jsonify({"status": 0, "message": "Please enter a valid param"})

    except Exception as e:
        return jsonify({"status": 0, "message": str(e)})


@app.route('/i_res/resident_forgot_password', methods=['POST'])
def resident_forgot_password():
    try:
        coll = mongo.db.resident_users
        value = request.json['value']
        for data in coll.find():
            mobile_number = data['mobile_number']
            # email = i['email_id']
            if mobile_number == value:
                otp = randint(1000, 9999)
                sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', mobile_number,
                        "Your OTP for IPERMIT RESIDENTIAL is " + str(otp))
                coll.find_one_and_update({'mobile_number': mobile_number}, {'$set': {'otp': str(otp)}})
                return jsonify({"status": 1, "message": "OTP generated successfully", "otp": str(otp)})
            # if email == value:
            #     otp = randint(1000, 9999)
            #     coll.find_one_and_update({'email_id': email}, {'$set': {'otp': str(otp)}})
            #     return jsonify({"status": 1, "message": "OTP generated successfully", "otp": str(otp)})
        else:
            return jsonify({"status": 0, "message": "Please enter a valid param"})

    except Exception as e:
        return jsonify({"status": 0, "message": str(e)})


###########################################change password#########################################

@app.route('/i_res/security_change_password', methods=['POST', 'GET'])
def security_change_password():
    coll = mongo.db.security_users
    value = str(request.json['value'])
    new_password = str(request.json['new_password'])
    confirm_password = str(request.json['confirm_password'])
    output = []
    try:
        if new_password != confirm_password:
            return jsonify({'status': 0, 'message': 'Please enter the same passwords.'})
        for data in coll.find():
            if data['mobile_number'] == value or data['email_id'] == value:
                coll.update({'mobile_number': str(value)},
                            {'$set': {'password': new_password, 'confirm_password': new_password}})
                coll.update({'email_id': str(value)},
                            {'$set': {'password': new_password, 'confirm_password': new_password}})
                output.append({'password': new_password})
        return jsonify({'status': 1, 'message': 'password changed successfully', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'result': str(e)})


@app.route('/i_res/resident_change_password', methods=['POST', 'GET'])
def resident_change_password():
    coll = mongo.db.resident_users
    value = str(request.json['value'])
    new_password = str(request.json['new_password'])
    confirm_password = str(request.json['confirm_password'])
    output = []
    try:
        if new_password != confirm_password:
            return jsonify({'status': 0, 'message': 'Please enter the same passwords.'})
        for data in coll.find():
            if data['mobile_number'] == value or data['email_id'] == value:
                coll.update({'mobile_number': str(value)},
                            {'$set': {'password': new_password, 'confirm_password': new_password}})
                coll.update({'email_id': str(value)},
                            {'$set': {'password': new_password, 'confirm_password': new_password}})
                output.append({'password': new_password})
        return jsonify({'status': 1, 'message': 'password changed successfully', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'result': str(e)})


######################################total visitors##########################################################

@app.route('/i_res/get_visitor_details', methods=['POST', 'GET'])
def get_visitor_details():
    # db = client.ipermit
    coll = mongo.db.visitors
    output = []
    sec_id = request.json['sec_id']
    for data in coll.find({'sec_id': sec_id}):
        splitting = data['created_time'].split(' ')
        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
        new_today_date = date_time_obj.strftime("%d/%m/%Y")
        # print(new_today_date)
        intime = new_today_date + ' ' + str(splitting[1])
        temp = {}
        temp['name'] = data['visiter_name']
        temp['community_id'] = data['community_id']
        temp['from'] = data['visitor_location']
        if 'body_temperature' not in data.keys():
            temp['body_temperature'] = ''
        else:
            temp['body_temperature'] = data['body_temperature']
        temp['mobile_number'] = data['mobile_number']

        temp['in_time'] = intime
        if 'outgoingtime' not in data.keys():
            temp['outgoingtime'] = ''
        else:
            splitting = data['outgoingtime'].split(' ')
            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
            new_today_date = date_time_obj.strftime("%d/%m/%Y")
            outtime = new_today_date + ' ' + str(splitting[1])
            temp['outgoingtime'] = outtime
        temp['duration'] = '25 min'
        temp['user_pic'] = data['user_pic']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Visitors details', 'result': output})


@app.route('/i_res/get_visitor_details_for_resident', methods=['POST', 'GET'])
def get_visitor_details_for_resident():
    # db = client.ipermit
    coll = mongo.db.visitors
    output = []
    e_id = request.json['e_id']
    for data in coll.find({'e_id': e_id}):
        temp = {}
        temp['name'] = data['visiter_name']
        temp['community_id'] = data['community_id']
        temp['from'] = data['visitor_location']
        if 'body_temperature' not in data.keys():
            temp['body_temperature'] = ''
        else:
            temp['body_temperature'] = data['body_temperature']
        temp['mobile_number'] = data['mobile_number']
        splitting = data['created_time'].split(' ')
        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
        new_today_date = date_time_obj.strftime("%d/%m/%Y")
        intime = new_today_date + ' ' + str(splitting[1])
        temp['in_time'] = intime
        if 'outgoingtime' not in data.keys():
            temp['outgoingtime'] = ''
        else:
            splitting = data['outgoingtime'].split(' ')
            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
            new_today_date = date_time_obj.strftime("%d/%m/%Y")
            outtime = new_today_date + ' ' + str(splitting[1])
            temp['outgoingtime'] = outtime
        temp['duration'] = '25 min'
        temp['user_pic'] = data['user_pic']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Visitors details', 'result': output})


#######################################visitor details ###############################################

@app.route('/i_res/visitor_signup', methods=['POST', 'GET'])
def visitor_signup():
    # db = client.ipermit
    coll = mongo.db.visitor_users
    coll1 = mongo.db.security_users
    coll2 = mongo.db.resident_users
    try:
        user_pic = request.json['user_pic']
        output = []
        # company_id=request.json['company_id']
        sec_id = request.json['sec_id']
        whom_to_meet = str(request.json['whom_to_meet'])
        # name_of_the_building = request.json['name_of_the_building']
        # community_id=request.json['community_id']
        block_number = request.json['block_number']
        flat_number = request.json['flat_number']
        reason_for_visit = request.json['reason_for_visit']
        # department_name = request.json['department_name']
        visiter_name = request.json['visiter_name']
        mask = request.json['mask']
        # id_proof_type = request.json['id_proof_type']
        # id_proof_number = str(request.json['id_proof_number'])
        mobile_number = request.json['mobile_number']
        body_temperature = request.json['body_temperature']
        # covid19_history = request.json['covid19_history']
        if re.search('[+!@#$%^&*_-]', body_temperature) is not None:
            return jsonify({'status': 0, 'message': 'Please Enter valid Number'})
        visitor_location = request.json['visitor_location']
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        current_dt = now_asia.strftime('%Y/%m/%d %H:%M')
        visit_id = randint(100, 999)
        # visit_id_list = [i['visit_id'] for i in coll.find()]
        # if len(visit_id_list) is 0:
        #     visit_id = 1
        # else:
        #     visit_id = int(visit_id_list[-1]) + 1
        user_pic = user_pic.encode()
        # data = coll.find()
        # for d in data:
        #     id = d['visit_id']
        #     if str(id) == str(visit_id):
        #         username = d['visit_id']
        try:
            e_id = request.json['e_id']
        except KeyError or ValueError:
            e_id = 0
        for emp in coll2.find({'e_id': e_id}):
            attention = 'You have a visitor named ' + visiter_name + ' from ' + visitor_location + '. Click to accept the request from security'
            resident_push_notifications(attention, emp['device_token'], sec_id, current_dt)
        for data in coll1.find({'sec_id': sec_id}):
            image_path = '/var/www/html/ires/visitor_photos/' + str(visit_id) + '.' + 'jpg'
            mongo_db_path = '/visitor_photos/' + str(visit_id) + '.' + 'jpg'
            with open(image_path, "wb")as fh:
                fh.write(base64.decodebytes(user_pic))
                coll.insert({'whom_to_meet': whom_to_meet, 'community_id': data['community_id'], 'sec_id': sec_id,

                             'reason_for_visit': reason_for_visit, 'mask': mask,
                             'visiter_name': visiter_name, 'e_id': e_id, 'status': 0,
                             'body_temperature': body_temperature,
                             'visit_id': visit_id, 'mobile_number': mobile_number, 'user_pic': mongo_db_path,
                             'flat_number': flat_number, 'block_number': block_number,
                             'visitor_location': visitor_location, 'created_time': current_dt})
                output.append(
                    {'whom_to_meet': whom_to_meet, 'community_name': data['community_id'], 'user_pic': mongo_db_path,
                     'reason_for_visit': reason_for_visit, 'sec_id': sec_id, 'status': 0,
                     'visiter_name': visiter_name,
                     'body_temperature': body_temperature, 'e_id': e_id, 'mask': mask,
                     'visit_id': visit_id, 'mobile_number': mobile_number, 'flat_number': flat_number,
                     'block_number': block_number,
                     'visitor_location': visitor_location, 'created_time': current_dt})

        return jsonify({'status': 1, 'message': "Visitor Sign Up successfull", 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'result': str(e)})


####################################profile settings for security ######################################################################

@app.route('/i_res/profile_settings', methods=['POST', 'GET'])
def profile_settings():
    # db = client.ipermit
    coll = mongo.db.security_users
    sec_id = request.json['sec_id']
    name = request.json['name']
    # sur_name=request.json['sur_name']
    # email_id=request.json['email_id']
    # mobile_number=request.json['mobile_number']
    designation = request.json['designation']
    emp_id = request.json['emp_id']
    block_number = request.json['block_number']
    language = request.json['language']
    try:
        language_type = request.json['language_type']
    except:
        language_type = ''
    output = []
    user_pic = request.json['user_pic']
    user_pic = user_pic.encode()
    for user in coll.find({'sec_id': sec_id}):
        image_path = '/var/www/html/ires/security_photos/' + str(sec_id) + '.' + 'jpg'
        mongo_db_path = '/security_photos/' + str(sec_id) + '.' + 'jpg'

        with open(image_path, "wb")as fh:
            fh.write(base64.decodebytes(user_pic))

            coll.update({'sec_id': int(sec_id)},
                        {'$set': {'name': name, 'designation': designation, 'langauage_type': language_type,
                                  'emp_id': emp_id, 'block_number': block_number, 'language': language,
                                  'user_pic': mongo_db_path}})
            output.append({'name': name, 'email_id': user['email_id'], 'mobile_number': user['mobile_number'],
                           'designation': designation, 'language_type': language_type,
                           'sec_id': sec_id, 'emp_id': emp_id, 'block_number': block_number, 'language': language,
                           'user_pic': mongo_db_path})
    return jsonify({'status': 1, 'message': 'Profile settings', 'result': output})


###########################################get employee profile details #############################################

@app.route('/i_res/get_resident_profile_details', methods=['POST', 'GET'])
def get_resident_profile_details():
    # db = client.ipermit
    coll = mongo.db.resident_users
    output = []
    e_id = request.json['e_id']
    for data in coll.find({'e_id': e_id}):
        temp = {}
        temp['name'] = data['name']
        temp['community_id'] = data['community_id']
        temp['mobile_number'] = data['mobile_number']
        temp['email_id'] = data['email_id']
        temp['language'] = data['language']
        temp['language_type'] = data['language_type']
        temp['flat_number'] = data['flat_number']
        temp['block_number'] = data['block_number']
        if 'block_number' not in data.keys():
            temp['block_number'] = ""
        else:
            temp['block_number'] = data['block_number']
        if 'user_pic' not in data.keys():
            temp['user_pic'] = ""
        else:
            temp['user_pic'] = data['user_pic']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Get resident profile details', 'result': output})


##############################################Reset password #############################################################

@app.route('/i_res/reset_password', methods=['POST'])
def reset_password():
    try:
        # db = client.ipermit
        coll = mongo.db.security_users
        sec_id = request.json['sec_id']
        # password = str(request.json['password'])
        new_password = request.json['new_password']
        confirm_password = request.json['confirm_password']
        if new_password != confirm_password:
            return jsonify({'status': 0, 'message': 'Password must match'})
        coll.find_one_and_update({'sec_id': sec_id}, {'$set': {'password': new_password}})
        return jsonify({'status': 1, "message": "Password changed successfully"})
    except Exception as e:
        return jsonify(status=0, message=str(e))


@app.route('/i_res/resident_reset_password', methods=['POST'])
def resident_reset_password():
    try:
        # db = client.ipermit
        coll = mongo.db.resident_users
        e_id = request.json['e_id']
        # password = str(request.json['password'])
        new_password = request.json['new_password']
        confirm_password = request.json['confirm_password']
        if new_password != confirm_password:
            return jsonify({'status': 0, 'message': 'Password must match'})
        coll.find_one_and_update({'e_id': e_id}, {'$set': {'password': new_password}})
        return jsonify({'status': 1, "message": "Password changed successfully"})
    except Exception as e:
        return jsonify(status=0, message=str(e))


###################################employee profile settings ##########################################################

@app.route('/i_res/resident_profile_settings', methods=['POST', 'GET'])
def resident_profile_settings():
    # db = client.ipermit
    coll = mongo.db.resident_users
    e_id = request.json['e_id']
    name = request.json['name']
    mobile_number = request.json['mobile_number']
    flat_number = request.json['flat_number']
    block_number = request.json['block_number']
    language = request.json['language']
    try:
        language_type = request.json['language_type']
    except:
        language_type = ''
    output = []
    user_pic = request.json['user_pic']
    user_pic = user_pic.encode()
    for user in coll.find({'e_id': e_id}):
        image_path = '/var/www/html/ires/resident_photos/' + str(e_id) + '.' + 'jpg'
        mongo_db_path = '/resident_photos/' + str(e_id) + '.' + 'jpg'

        with open(image_path, "wb")as fh:
            fh.write(base64.decodebytes(user_pic))

            coll.update({'e_id': int(e_id)},
                        {'$set': {'name': name, 'language_type': language_type,'flat_number':flat_number,
                                   'block_number': block_number, 'language': language,'mobile_number':mobile_number,
                                  'user_pic': mongo_db_path}})
            output.append({'name': name, 'email_id': user['email_id'], 'mobile_number': mobile_number,
                            'language_type': language_type,'flat_number':flat_number,
                           'e_id': e_id,  'block_number': block_number, 'language': language,
                           'user_pic': mongo_db_path})
    return jsonify({'status': 1, 'message': 'Profile settings', 'result': output})


##############################security profile settings #############################################################

@app.route('/i_res/get_security_profile_settings', methods=['POST', 'GET'])
def get_security_profile_settings():
    coll = mongo.db.security_users
    output = []
    sec_id = request.json['sec_id']
    for data in coll.find({'sec_id': sec_id}):
        temp = {}
        if 'user_pic' not in data.keys():
            temp['user_pic'] = ''
        else:
            temp['user_pic'] = data['user_pic']
        temp['name'] = data['name']
        temp['mobile_number'] = data['mobile_number']
        temp['email_id'] = data['email_id']
        temp['language_type'] = data['language_type']
        temp['sec_id'] = sec_id
        if 'designation' not in data.keys():
            temp['designation'] = ''
        else:
            temp['designation'] = data['designation']
        temp['flat_number'] = data['flat_number']
        temp['block_number'] = data['block_number']
        # if 'department' not in data.keys():
        #     temp['department'] = ''
        # else:
        #     temp['department']=data['department']

        if 'language' not in data.keys():

            temp['language'] = ''
        else:
            temp['language'] = data['language']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Get security profile settings  successfully', 'result': output})


###############################employee profile settings #####################################################

@app.route('/i_res/get_resident_profile_settings', methods=['POST', 'GET'])
def get_resident_profile_settings():
    coll = mongo.db.resident_users
    output = []
    e_id = request.json['e_id']
    for data in coll.find({'e_id': e_id}):
        temp = {}
        if 'user_pic' not in data.keys():
            temp['user_pic'] = ''
        else:
            temp['user_pic'] = data['user_pic']
        temp['name'] = data['name']
        temp['mobile_number'] = data['mobile_number']
        temp['email_id'] = data['email_id']
        temp['e_id'] = e_id
        if 'designation' not in data.keys():
            temp['designation'] = ''
        else:
            temp['designation'] = data['designation']
        temp['flat_number'] = data['flat_number']
        temp['block_number'] = data['block_number']
        # if 'department' not in data.keys():
        #     temp['department'] = ''
        # else:
        #     temp['department']=data['department']

        if 'language' not in data.keys():

            temp['language'] = ''
        else:
            temp['language'] = data['language']
        temp['language_type'] = data['language_type']
        output.append(temp)
    return jsonify({'status': 1, 'message': 'Get  resident profile settings  successfully', 'result': output})


##################################visitor pre bookings ##############################################################

@app.route('/i_res/visitor_pre_booking', methods=['POST'])
def visitor_pre_booking():
    coll = mongo.db.visitor_pre_bookings
    coll1 = mongo.db.security_users
    coll2 = mongo.db.community_list
    coll3 = mongo.db.resident_users
    try:
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        current_dt = now_asia.strftime('%Y/%m/%d %H:%M')

        e_id = request.json['e_id']
        community_id = request.json['community_id']
        date = request.json['date']
        select_time = request.json['select_time']
        vehicle_type = request.json['vehicle_type']
        try:
            visitor_mobile_number = request.json['visitor_mobile_number']
        except:
            visitor_mobile_number = ''

        otp = randint(1000, 9999)
        for li in coll2.find({'community_id': community_id}):
            for data in coll3.find({'e_id': e_id}):
                sendSMS('iA2vM8edy2o-nnkGgZKppyeiNpeqbJobbiKanhhXKj', visitor_mobile_number,
                        "Your appointment at  " + li['community_name'] + "  with " + data[
                            'name'] + ",  is scheduled on " + date + " " + select_time + ".  Your OTP Verification Code is " + str(
                            otp))

        visitor_type = request.json['visitor_type']
        visitor_name = request.json['visitor_name']
        visitor_location = request.json['visitor_location']
        try:
            vehicle_number = request.json['vehicle_number']
        except:
            vehicle_number = ''

        try:
            select_week = request.json['select_week']
        except:
            select_week = 7
        id_list = [i['id'] for i in coll.find()]
        if len(id_list) is 0:
            id = 1
        else:
            id = int(id_list[-1]) + 1

        # try:
        #     sec_id = request.json['sec_id']
        # except KeyError or ValueError:
        #     sec_id=1
        output = []
        for sec in coll1.find({'community_id': community_id}):
            attention = 'You have a visitor named ' + visitor_name + ' from ' + visitor_location + '. Click to accept the request from resident'
            security_push_notifications(attention, sec['device_token'], e_id, current_dt)

            coll.insert(
                {'community_id': community_id, 'e_id': e_id, 'created_time': current_dt, 'vehicle_type': vehicle_type,
                 'visitor_type': visitor_type,
                 'vehicle_number': vehicle_number, 'date': date, 'select_time': select_time, 'status': 1,
                 'sec_id': sec['sec_id'], 'visitor_mobile_number': visitor_mobile_number,
                 'select_week': select_week, 'id': id, 'visitor_name': visitor_name,
                 'visitor_location': visitor_location, 'otp': str(otp), 'verify_status': False
                 })
            output.append(
                {'community_id': community_id, 'e_id': e_id, 'created_time': current_dt, 'vehicle_type': vehicle_type,
                 'otp': str(otp),
                 'visitor_type': visitor_type, 'status': 1, 'visitor_mobile_number': visitor_mobile_number,
                 'vehicle_number': vehicle_number, 'date': date, 'sec_id': sec['sec_id'], 'verify_status': False,
                 'select_time': select_time, 'visitor_name': visitor_name, 'visitor_location': visitor_location,
                 'select_week': select_week, 'id': id
                 })
        return jsonify({'status': 1, 'message': 'Visitor pre bookings', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


################################### name list ###############################################################

@app.route('/i_res/security_name_list', methods=['POST', 'GET'])
def security_name_list():
    coll = mongo.db.security_users
    try:
        community_id = request.json['community_id']
        output = []
        for li in coll.find({'community_id': community_id}):
            output.append(
                {'sec_id': li['sec_id'], 'name': li['name'],
                 })
        return jsonify({'status': 1, 'message': 'Security name list', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/resident_name_list', methods=['POST', 'GET'])
def resident_name_list():
    coll = mongo.db.resident_users
    try:
        community_id = request.json['community_id']
        output = []
        for li in coll.find({'community_id': community_id}):
            output.append(
                {'e_id': li['e_id'], 'name': li['name'],
                 })
        return jsonify({'status': 1, 'message': 'Resident name list', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


###############################post notifications ################################################################

@app.route('/i_res/security_push_notifications/<message_body><registration_id><e_id><time>', methods=['POST'])
def security_push_notifications(message_body, registration_id, e_id, time):
    push_service = FCMNotification(
        api_key="AAAAOeMx4m8:APA91bG1cRujUcqXehsMw6HNEAGnn3VOhHbpapupmBdjIwpYC9-L-uqpeXRqr2TPFO5YIh5my-Z6KeVjoqM6t5ygqWa-6loHSN9gB-qhVAhI-YDlGJVhFjMsNmHXV7mMCTMuKoDF6VXV")
    coll1 = mongo.db.security_notification
    coll = mongo.db.security_users
    # coll1=mongo.db.employee_users,"badge":20,"sound":"Default"
    output = []
    # registration_id = request.json['registration_id']
    message_title = "IPERMIT RESIDENTIAL"
    # sound="default"
    # badge= 1
    for data in coll.find({'device_token': registration_id}):
        user = data['sec_id']
        coll1.insert({"registration_id": registration_id, 'message_title': message_title, 'message_body': message_body,
                      'time': time,
                      'sec_id': user, 'sender': e_id})
        output.append({"registration_id": registration_id, 'message_title': message_title, 'message_body': message_body,
                       'time': time,
                       'sec_id': user, 'sender': e_id})
    result = push_service.notify_single_device(registration_id=registration_id, message_title=message_title,
                                               sound="/var/www/html/tpermit/notification_ring.mp3", badge=1,
                                               message_body=message_body)
    print(result)
    return jsonify({'status': 1, 'message': 'message sent successfully to security', 'result': output})


@app.route('/i_res/resident_push_notifications/<message_body><registration_id><sec_id><time>', methods=['POST'])
def resident_push_notifications(message_body, registration_id, sec_id, time):
    push_service = FCMNotification(
        api_key="AAAAOeMx4m8:APA91bG1cRujUcqXehsMw6HNEAGnn3VOhHbpapupmBdjIwpYC9-L-uqpeXRqr2TPFO5YIh5my-Z6KeVjoqM6t5ygqWa-6loHSN9gB-qhVAhI-YDlGJVhFjMsNmHXV7mMCTMuKoDF6VXV")
    coll1 = mongo.db.resident_notification
    # coll=mongo.db.security_users
    coll = mongo.db.resident_users
    output = []
    # registration_id = request.json['registration_id']
    message_title = "IPERMIT RESIDENTIAL"
    for data in coll.find({'device_token': registration_id}):
        user = data['e_id']
        coll1.insert({"registration_id": registration_id, 'message_title': message_title, 'message_body': message_body,
                      'time': time,
                      'e_id': user, 'sender': sec_id})
        output.append({"registration_id": registration_id, 'message_title': message_title, 'message_body': message_body,
                       'time': time,
                       'e_id': user, 'sender': sec_id})
    result = push_service.notify_single_device(registration_id=registration_id, message_title=message_title,
                                               sound="/var/www/html/tpermit/notification_ring.mp3", badge=1,
                                               message_body=message_body)
    print(result)
    return jsonify({'status': 1, 'message': 'message sent successfully to resident', 'result': output})


################################# get notifications ####################################################

@app.route('/i_res/get_security_notifications', methods=['POST'])
def get_security_notifications():
    data = mongo.db.security_notification
    # coll=mongo.db.security_users
    # coll1=mongo.db.employee_users
    sec_id = request.json['sec_id']
    output = []
    for data in data.find():
        if data['sec_id'] == sec_id:
            output.append(
                {'sec_id': sec_id, 'message_body': data['message_body'], 'message_title': data['message_title'],
                 'sender': data['sender'], 'time': data['time']})
    output.reverse()
    return jsonify({'status': 1, 'message': ' Security notifications list', 'result': output})


@app.route('/i_res/get_resident_notifications', methods=['POST'])
def get_resident_notifications():
    data = mongo.db.resident_notification
    # coll=mongo.db.security_users
    # coll1=mongo.db.employee_users
    e_id = request.json['e_id']
    output = []
    for data in data.find():
        if data['e_id'] == e_id:
            output.append({'e_id': e_id, 'message_body': data['message_body'], 'message_title': data['message_title'],
                           'sender': data['sender'], 'time': data['time']})
    output.reverse()
    return jsonify({'status': 1, 'message': ' Resident notifications list', 'result': output})


#################################get visitor list #############################################

@app.route('/i_res/get_visitor_requests_list', methods=['POST'])
def get_visitor_requests_list():
    coll = mongo.db.resident_users
    coll1 = mongo.db.security_users
    coll2 = mongo.db.visitor_users
    coll3 = mongo.db.visitor_pre_bookings
    # sec_id=request.json['sec_id']
    e_id = request.json['e_id']
    # company_id=request.json['company_id']
    try:
        output = []
        for li in coll2.find():
            temp = {}
            if li['e_id'] == e_id:
                temp['visitor_name'] = li['visiter_name']
                # temp['company_id'] = li['company_id']
                # temp['visitor_location'] = li['visitor_location']
                temp['visit_id'] = li['visit_id']
                temp['mobile_number'] = li['mobile_number']

                splitting = li['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime
                temp['visitor_location'] = li['visitor_location']
                # temp['duration'] = '25 min'
                temp['user_pic'] = li['user_pic']
                temp['mask'] = li['mask']
                temp['whom_to_meet'] = li['whom_to_meet']
                if 'body_temperature' not in li.keys():
                    temp['body_temperature'] = ''
                else:
                    temp['body_temperature'] = li['body_temperature']
                output.append(temp)
        return jsonify({'status': 1, 'message': 'Get Visitors request list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


##########################visitor status ###########################################
# @app.route('/i_permit/visitor_status', methods=['POST'])
# def visitor_status():
#     coll = mongo.db.visitor_users
#     try:
#         status = request.json['status']
#         # e_id = request.json['e_id']
#         visit_id=request.json['visit_id']
#         coll.update({'visit_id': visit_id}, {'$set':{'status': status}})
#         return jsonify({'status': 1, 'message': 'Visitor status updated successfully'})
#     except Exception as e:

#         return jsonify({'status': 0, 'message': str(e)})
# @app.route('/i_permit/visitor_status', methods=['POST'])
# def visitor_status():
#     coll = mongo.db.visitor_users
#     coll1 = mongo.db.employee_users
#     coll2 = mongo.db.security_users
#     try:
#         status = request.json['status']
#         visit_id=request.json['visit_id']
#         coll.update({'visit_id': visit_id}, {'$set':{'status': status}})
#         for li in coll.find({"visit_id":visit_id}):
#             eid=li['e_id']
#             sid=li['sec_id']
#             for lt in coll1.find({"e_id":eid}):
#                 for ls in coll2.find({'sec_id':sid}):
#                     attention = lt['name'] + "has"+status+ls["name"]+"request"
#                     security_push_notifications(attention, ls['device_token'], eid)
#         return jsonify({'status': 1, 'message': 'Visitor status updated successfully'})
#     except Exception as e:
#         return jsonify({'status': 0, 'message': str(e)})
#
@app.route('/i_res/visitor_status', methods=['POST'])
def visitor_status():
    coll = mongo.db.visitor_users
    coll1 = mongo.db.resident_users
    coll2 = mongo.db.security_users
    coll3 = mongo.db.visitors
    try:
        status = request.json['status']
        visit_id = request.json['visit_id']
        coll.update({'visit_id': int(visit_id)}, {'$set': {'status': status}})
        for li in coll.find({"visit_id": visit_id}):
            eid = li['e_id']
            sid = li['sec_id']
            coll3.insert(
                {"whom_to_meet": li["whom_to_meet"], "sec_id": li["sec_id"],"e_id": li["e_id"],
                 "community_id": li["community_id"], "reason_for_visit": li["reason_for_visit"],
                 "visiter_name": li["visiter_name"], "body_temperature": li["body_temperature"],
                 "visit_id": li["visit_id"], "mobile_number": li["mobile_number"], "user_pic": li["user_pic"],
                 "visitor_location": li["visitor_location"], "created_time": li["created_time"]
                    , "status": li["status"], 'flat_number': li['flat_number'], 'block_number': li['block_number'],
                 'mask': li['mask']}
                )
            coll.remove({'visit_id': visit_id})
            for lt in coll1.find({"e_id": int(eid)}):
                for ls in coll2.find({'sec_id': int(sid)}):
                    if status == 0:
                        attention = lt['name'] + " has " + "ACCEPT " + ls["name"] + " request"
                        security_push_notifications(attention, ls['device_token'], eid)
                    if status == 2:
                        attention = lt['name'] + " has " + "DENIED " + ls["name"] + " request"
                        security_push_notifications(attention, ls['device_token'], eid)

        return jsonify({'status': 1, 'message': 'Visitor status updated successfully'})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})

####################################logs ###########################################
# @app.route('/t_permit/logs_for_security', methods=['POST'])
# def logs_for_security():
#
#     coll2 = mongo.db.visitors
#     coll3 = mongo.db.visitor_pre_bookings
#     sec_id=request.json['sec_id']
#     try:
#         output=[]
#         Current_Date_Formatted = datetime.datetime.today().strftime('%Y/%m/%d')  # format the date to ddmmyyyy
#         current_date = datetime.datetime.strptime(Current_Date_Formatted, '%Y/%m/%d')
#         for li in coll2.find({'sec_id':sec_id}):
#             # temp = {}
#             date_time_obj = datetime.datetime.strptime(li['created_time'], '%Y/%m/%d %H:%M')
#             user_date = datetime.datetime.strftime(date_time_obj, '%Y/%m/%d')
#             date_time = datetime.datetime.strptime(user_date, '%Y/%m/%d')
#             if current_date == date_time:
#                 intime = li['created_time']
#                 # tdelta = datetime.strptime(res1[1], FMT) - datetime.strptime(res[1], FMT)
#                 temp = {}
#                 temp['visitor_name'] = li['visiter_name']
#                 temp['visit_id']=li['visit_id']
#                 temp['company_id'] = li['company_id']
#                 temp['visitor_location'] = li['visitor_location']
#                 temp['mobile_number'] = li['mobile_number']
#                 temp['visitor_mobile_number'] = ''
#                 temp['in_time'] = li['created_time']
#                 if 'outgoingtime' not in li.keys():
#                     temp['outgoingtime'] = ''
#                     temp['duration']=''
#                 else:
#                     temp['outgoingtime'] = li['outgoingtime']
#                     outtime = li['outgoingtime']
#                     res = intime.split(' ')
#                     res1 = outtime.split(' ')
#                     FMT = '%H:%M'
#                     temp['duration'] = str(datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
#                 temp['user_pic'] = li['user_pic']
#                 temp['status']=li['status']
#                 temp['verify_status']=''
#                 output.append(temp)
#         for lv in coll3.find({'sec_id': sec_id}):
#             date_time_obj1 = datetime.datetime.strptime(lv['date'], '%Y/%m/%d')
#             user_date1 = datetime.datetime.strftime(date_time_obj1, '%Y/%m/%d')
#             date_time_two = datetime.datetime.strptime(user_date1, '%Y/%m/%d')
#             intime=lv['created_time']
#             if current_date == date_time_two:
#                 temp = {}
#                 temp['visitor_name'] = lv['visitor_name']
#                 temp['visit_id'] = lv['id']
#                 temp['company_id'] = lv['company_id']
#                 temp['visitor_location'] = lv['visitor_location']
#                 temp['mobile_number'] = ''
#                 temp['visitor_mobile_number']=lv['visitor_mobile_number']
#                 temp['in_time'] = lv['created_time']
#                 # if 'outgoingtime' not in lv.keys():
#                 if 'outgoingtime' not in lv.keys():
#                     temp['outgoingtime'] = ''
#                     temp['duration'] = ''
#                 else:
#                     temp['outgoingtime'] = lv['outgoingtime']
#                     outtime = lv['outgoingtime']
#                     res = intime.split(' ')
#                     res1 = outtime.split(' ')
#                     FMT = '%H:%M'
#                     temp['duration'] = str(
#                         datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
#                 temp['user_pic'] = ''
#                 temp['status'] = lv['status']
#                 temp['verify_status'] = lv['verify_status']
#                 output.append(temp)
#         output.reverse()
#         finaloutput = {}
#         finaloutput['status'] = 1
#         # finaloutput['login_status'] = 1
#         finaloutput['message'] = 'Get Visitors details'
#         finaloutput['result'] = output
#         return jsonify(finaloutput)
#     except Exception as e:
#         return jsonify({'status': 0, 'message': str(e)})
#
# @app.route('/t_permit/logs_for_employee', methods=['POST'])
# def logs_for_employee():
#     # coll=mongo.db.employee_users
#     # coll1 = mongo.db.security_users
#     coll2 = mongo.db.visitors
#     coll3 = mongo.db.visitor_pre_bookings
#     e_id=request.json['e_id']
#     # e_id=request.json['e_id']
#     # company_id=request.json['company_id']
#     # details=coll2.find({'sec_id':sec_id})
#     try:
#         output=[]
#         Current_Date_Formatted = datetime.datetime.today().strftime('%Y/%m/%d')  # format the date to ddmmyyyy
#         current_date = datetime.datetime.strptime(Current_Date_Formatted, '%Y/%m/%d')
#         print(current_date)
#         for li in coll2.find({'e_id':e_id}):
#             # temp = {}
#             date_time_obj = datetime.datetime.strptime(li['created_time'], '%Y/%m/%d %H:%M')
#             user_date = datetime.datetime.strftime(date_time_obj, '%Y/%m/%d')
#             date_time = datetime.datetime.strptime(user_date, '%Y/%m/%d')
#             print(date_time)
#             if current_date == date_time:
#                 intime = li['created_time']
#
#                 # tdelta = datetime.strptime(res1[1], FMT) - datetime.strptime(res[1], FMT)
#                 temp = {}
#                 temp['visitor_name'] = li['visiter_name']
#                 temp['visit_id'] = li['visit_id']
#                 temp['company_id'] = li['company_id']
#                 temp['visitor_location'] = li['visitor_location']
#                 temp['visitor_mobile_number'] =''
#                 temp['mobile_number'] = li['mobile_number']
#                 temp['in_time'] = li['created_time']
#                 if 'outgoingtime' not in li.keys():
#                     temp['outgoingtime'] = ''
#                     temp['duration']=''
#                 else:
#                     temp['outgoingtime'] = li['outgoingtime']
#                     outtime = li['outgoingtime']
#                     res = intime.split(' ')
#                     res1 = outtime.split(' ')
#                     FMT = '%H:%M'
#                     temp['duration'] = str(datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
#                 temp['user_pic'] = li['user_pic']
#                 temp['status'] = li['status']
#                 temp['verify_status'] = ''
#                 output.append(temp)
#
#         for lv in coll3.find({'e_id': e_id}):
#             date_time_obj1 = datetime.datetime.strptime(lv['date'], '%Y/%m/%d')
#             user_date1 = datetime.datetime.strftime(date_time_obj1, '%Y/%m/%d')
#             date_time_two = datetime.datetime.strptime(user_date1, '%Y/%m/%d')
#             intime=lv['created_time']
#             if current_date == date_time_two:
#                 temp = {}
#                 temp['visitor_name'] = lv['visitor_name']
#                 temp['visit_id'] = lv['id']
#                 temp['company_id'] = lv['company_id']
#                 temp['visitor_location'] = lv['visitor_location']
#                 temp['visitor_mobile_number']=lv['visitor_mobile_number']
#                 temp['mobile_number'] = ''
#                 temp['in_time'] = lv['created_time']
#                 # if 'outgoingtime' not in lv.keys():
#                 if 'outgoingtime' not in lv.keys():
#                     temp['outgoingtime'] = ''
#                     temp['duration'] = ''
#                 else:
#                     temp['outgoingtime'] = lv['outgoingtime']
#                     outtime = lv['outgoingtime']
#                     res = intime.split(' ')
#                     res1 = outtime.split(' ')
#                     FMT = '%H:%M'
#                     temp['duration'] = str(
#                         datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
#                 temp['user_pic'] = ''
#                 temp['status'] = lv['status']
#                 temp['verify_status'] = lv['verify_status']
#                 output.append(temp)
#         output.reverse()
#         finaloutput = {}
#         finaloutput['status'] = 1
#         # finaloutput['login_status'] = 1
#         finaloutput['message'] = 'Get Visitors details'
#         finaloutput['result'] = output
#         return jsonify(finaloutput)
#     except Exception as e:
#         return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/logs_for_security', methods=['POST'])
def logs_for_security():
    coll2 = mongo.db.visitors
    coll3 = mongo.db.visitor_pre_bookings
    sec_id = request.json['sec_id']
    try:
        output = []
        Current_Date_Formatted = datetime.datetime.today().strftime('%Y/%m/%d')  # format the date to ddmmyyyy
        current_date = datetime.datetime.strptime(Current_Date_Formatted, '%Y/%m/%d')
        for li in coll2.find({'sec_id': sec_id}):
            # temp = {}
            date_time_obj = datetime.datetime.strptime(li['created_time'], '%Y/%m/%d %H:%M')
            user_date = datetime.datetime.strftime(date_time_obj, '%Y/%m/%d')
            date_time = datetime.datetime.strptime(user_date, '%Y/%m/%d')
            if current_date == date_time:
                intime = li['created_time']
                # tdelta = datetime.strptime(res1[1], FMT) - datetime.strptime(res[1], FMT)
                temp = {}
                temp['visitor_name'] = li['visiter_name']
                temp['visitor_type'] = ''
                temp['visit_id'] = li['visit_id']
                temp['community_id'] = li['community_id']
                if 'body_temperature' not in li.keys():
                    temp['body_temperature'] = ''
                else:
                    temp['body_temperature'] = li['body_temperature']
                temp['visitor_location'] = li['visitor_location']
                temp['mobile_number'] = li['mobile_number']
                temp['visitor_mobile_number'] = ''

                splitting = li['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime1 = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime1
                temp['whom_to_meet'] = li['whom_to_meet']
                if 'outgoingtime' not in li.keys():
                    temp['outgoingtime'] = ''
                    temp['duration'] = ''
                else:
                    splitting = li['outgoingtime'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    outtime = new_today_date + ' ' + str(splitting[1])

                    temp['outgoingtime'] = outtime
                    outtime = li['outgoingtime']
                    res = intime.split(' ')
                    res1 = outtime.split(' ')
                    FMT = '%H:%M'
                    temp['duration'] = str(
                        datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                    coll2.update({"visit_id": li['visit_id']}, {'$set': {"duration": str(
                        datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                temp['user_pic'] = li['user_pic']
                temp['status'] = li['status']
                temp['verify_status'] = ''
                output.append(temp)
        for lv in coll3.find({'sec_id': sec_id}):
            date_time_obj1 = datetime.datetime.strptime(lv['date'], '%Y/%m/%d')
            user_date1 = datetime.datetime.strftime(date_time_obj1, '%Y/%m/%d')
            date_time_two = datetime.datetime.strptime(user_date1, '%Y/%m/%d')
            intime = lv['created_time']
            if lv['visitor_type'] == 1:
                if lv['select_week'] == 0:
                    if datetime.datetime.today().strftime('%A') == "Sunday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:

                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 1:
                    if datetime.datetime.today().strftime('%A') == "Monday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 2:
                    if datetime.datetime.today().strftime('%A') == "Tuesday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 3:
                    if datetime.datetime.today().strftime('%A') == "Wednesday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 4:
                    if datetime.datetime.today().strftime('%A') == "Thursday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 5:

                    if datetime.datetime.today().strftime('%A') == "Friday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 6:
                    if datetime.datetime.today().strftime('%A') == "Saturday":
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

            if lv['visitor_type'] == 0:

                if current_date == date_time_two:
                    temp = {}
                    temp['visitor_name'] = lv['visitor_name']
                    temp['visit_id'] = lv['id']
                    temp['visitor_type'] = lv['visitor_type']
                    temp['community_id'] = lv['community_id']
                    temp['visitor_location'] = lv['visitor_location']
                    temp['mobile_number'] = ''
                    if 'body_temperature' not in lv.keys():
                        temp['body_temperature'] = ''
                    else:
                        temp['body_temperature'] = lv['body_temperature']
                    temp['visitor_mobile_number'] = lv['visitor_mobile_number']

                    splitting = lv['created_time'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    intime1 = new_today_date + ' ' + str(splitting[1])

                    temp['in_time'] = intime1
                    # if 'outgoingtime' not in lv.keys():
                    if 'outgoingtime' not in lv.keys():
                        temp['outgoingtime'] = ''
                        temp['duration'] = ''
                    else:
                        splitting = lv['outgoingtime'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        outtime = new_today_date + ' ' + str(splitting[1])

                        temp['outgoingtime'] = outtime
                        outtime = lv['outgoingtime']
                        res = intime.split(' ')
                        res1 = outtime.split(' ')
                        FMT = '%H:%M'
                        temp['duration'] = str(
                            datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                        coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                            datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                    temp['user_pic'] = ''
                    temp['whom_to_meet'] = ""
                    temp['status'] = lv['status']
                    temp['verify_status'] = lv['verify_status']
                    output.append(temp)
        # output.reverse()
        output.sort(key=lambda item: item['in_time'], reverse=True)
        finaloutput = {}
        finaloutput['status'] = 1
        # finaloutput['login_status'] = 1
        finaloutput['message'] = 'Get Visitors details'
        finaloutput['result'] = output
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/logs_for_resident', methods=['POST'])
def logs_for_resident():
    # coll=mongo.db.resident_users
    # coll1 = mongo.db.security_users
    coll2 = mongo.db.visitors
    coll3 = mongo.db.visitor_pre_bookings
    e_id = request.json['e_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    # details=coll2.find({'sec_id':sec_id})
    try:
        output = []
        Current_Date_Formatted = datetime.datetime.today().strftime('%Y/%m/%d')  # format the date to ddmmyyyy
        current_date = datetime.datetime.strptime(Current_Date_Formatted, '%Y/%m/%d')
        # print(current_date)
        for li in coll2.find({'e_id': e_id}):
            # temp = {}
            date_time_obj = datetime.datetime.strptime(li['created_time'], '%Y/%m/%d %H:%M')
            user_date = datetime.datetime.strftime(date_time_obj, '%Y/%m/%d')
            date_time = datetime.datetime.strptime(user_date, '%Y/%m/%d')
            # print(date_time)
            if current_date == date_time:
                intime = li['created_time']

                # tdelta = datetime.strptime(res1[1], FMT) - datetime.strptime(res[1], FMT)
                temp = {}
                temp['visitor_name'] = li['visiter_name']
                temp['visit_id'] = li['visit_id']
                temp['visitor_type'] = ''
                temp['community_id'] = li['community_id']
                temp['visitor_location'] = li['visitor_location']
                temp['visitor_mobile_number'] = ''
                if 'body_temperature' not in li.keys():
                    temp['body_temperature'] = ''
                else:
                    temp['body_temperature'] = li['body_temperature']
                temp['mobile_number'] = li['mobile_number']

                splitting = li['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime1 = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime1
                temp['whom_to_meet'] = li['whom_to_meet']
                if 'outgoingtime' not in li.keys():
                    temp['outgoingtime'] = ''
                    temp['duration'] = ''
                else:
                    splitting = li['outgoingtime'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    outtime = new_today_date + ' ' + str(splitting[1])

                    temp['outgoingtime'] = outtime
                    outtime = li['outgoingtime']
                    res = intime.split(' ')
                    res1 = outtime.split(' ')
                    FMT = '%H:%M'
                    temp['duration'] = str(
                        datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                    coll2.update({"visit_id": li['visit_id']}, {'$set': {"duration": str(
                        datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                temp['user_pic'] = li['user_pic']
                temp['status'] = li['status']
                temp['verify_status'] = ''
                output.append(temp)

        for lv in coll3.find({'e_id': e_id}):
            date_time_obj1 = datetime.datetime.strptime(lv['date'], '%Y/%m/%d')
            user_date1 = datetime.datetime.strftime(date_time_obj1, '%Y/%m/%d')
            date_time_two = datetime.datetime.strptime(user_date1, '%Y/%m/%d')
            intime = lv['created_time']
            if lv['visitor_type'] == 1:
                print('yes')
                if lv['select_week'] == 0:
                    print(0)
                    if datetime.datetime.today().strftime('%A') == "Sunday":

                        print('sunday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 1:
                    print(1)
                    if datetime.datetime.today().strftime('%A') == "Monday":
                        print('monday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 2:
                    print(2)
                    if datetime.datetime.today().strftime('%A') == "Tuesday":
                        print('tuesday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 3:
                    print(3)
                    if datetime.datetime.today().strftime('%A') == "Wednesday":
                        print('wednesday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 4:
                    print(4)
                    if datetime.datetime.today().strftime('%A') == "Thursday":
                        print('thursday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 5:
                    print(5)
                    if datetime.datetime.today().strftime('%A') == "Friday":
                        print('friday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

                if lv['select_week'] == 6:
                    print(6)
                    if datetime.datetime.today().strftime('%A') == "Saturday":
                        print('saturday')
                        temp = {}
                        temp['visitor_name'] = lv['visitor_name']
                        temp['visit_id'] = lv['id']
                        temp['visitor_type'] = lv['visitor_type']
                        temp['community_id'] = lv['community_id']
                        temp['visitor_location'] = lv['visitor_location']
                        if 'body_temperature' not in lv.keys():
                            temp['body_temperature'] = ''
                        else:
                            temp['body_temperature'] = lv['body_temperature']
                        temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                        temp['mobile_number'] = ''

                        splitting = lv['created_time'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        intime1 = new_today_date + ' ' + str(splitting[1])

                        temp['in_time'] = intime1
                        # if 'outgoingtime' not in lv.keys():
                        if 'outgoingtime' not in lv.keys():
                            temp['outgoingtime'] = ''
                            temp['duration'] = ''
                        else:
                            splitting = lv['outgoingtime'].split(' ')
                            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                            new_today_date = date_time_obj.strftime("%d/%m/%Y")
                            outtime = new_today_date + ' ' + str(splitting[1])

                            temp['outgoingtime'] = outtime
                            outtime = lv['outgoingtime']
                            res = intime.split(' ')
                            res1 = outtime.split(' ')
                            FMT = '%H:%M'
                            temp['duration'] = str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                            coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                                datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                        temp['user_pic'] = ''
                        temp['whom_to_meet'] = ""
                        temp['status'] = lv['status']
                        temp['verify_status'] = lv['verify_status']
                        output.append(temp)

            if lv['visitor_type'] == 0:
                print('ok')
                if current_date == date_time_two:
                    print(current_date)
                    temp = {}
                    temp['visitor_name'] = lv['visitor_name']
                    temp['visit_id'] = lv['id']
                    temp['community_id'] = lv['community_id']
                    temp['visitor_type'] = lv['visitor_type']
                    if 'body_temperature' not in lv.keys():
                        temp['body_temperature'] = ''
                    else:
                        temp['body_temperature'] = lv['body_temperature']
                    temp['visitor_location'] = lv['visitor_location']
                    temp['visitor_mobile_number'] = lv['visitor_mobile_number']
                    temp['mobile_number'] = ''

                    splitting = lv['created_time'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    intime1 = new_today_date + ' ' + str(splitting[1])

                    temp['in_time'] = intime1
                    # if 'outgoingtime' not in lv.keys():
                    if 'outgoingtime' not in lv.keys():
                        temp['outgoingtime'] = ''
                        temp['duration'] = ''
                    else:
                        splitting = lv['outgoingtime'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        outtime = new_today_date + ' ' + str(splitting[1])

                        temp['outgoingtime'] = outtime
                        outtime = lv['outgoingtime']
                        res = intime.split(' ')
                        res1 = outtime.split(' ')
                        FMT = '%H:%M'
                        temp['duration'] = str(
                            datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))
                        coll3.update({"id": lv['id']}, {'$set': {"duration": str(
                            datetime.datetime.strptime(res1[1], FMT) - datetime.datetime.strptime(res[1], FMT))}})
                    temp['user_pic'] = ''
                    temp['whom_to_meet'] = ""
                    temp['status'] = lv['status']
                    temp['verify_status'] = lv['verify_status']
                    output.append(temp)
        # output.reverse()
        output.sort(key=lambda item: item['in_time'], reverse=True)
        finaloutput = {}
        finaloutput['status'] = 1
        # finaloutput['login_status'] = 1
        finaloutput['message'] = 'Get Visitors details'
        finaloutput['result'] = output
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


##########################################################activity screen #######################################################################

@app.route('/i_res/get_security_prebooking_list', methods=['POST'])
def get_security_prebooking_list():
    coll = mongo.db.visitor_pre_bookings
    sec_id = request.json['sec_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    try:
        output = []
        for li in coll.find():
            temp = {}
            if li['sec_id'] == sec_id:
                temp['visitor_name'] = li['visitor_name']
                temp['visitor_mobile_number'] = li['visitor_mobile_number']
                temp['community_id'] = li['community_id']
                temp['visitor_location'] = li['visitor_location']
                temp['select_time'] = li['select_time']
                temp['vehicle_type'] = li['vehicle_type']
                if 'body_temperature' not in li.keys():
                    temp['body_temperature'] = ''
                else:
                    temp['body_temperature'] = li['body_temperature']
                if 'duration' not in li.keys():
                    temp['duration'] = ''
                else:
                    temp['duration'] = li['duration']
                temp['date'] = li['date']

                temp['select_week'] = li['select_week']

                splitting = li['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime
                if 'outgoingtime' not in li.keys():
                    temp['outgoingtime'] = ''

                else:
                    splitting = li['outgoingtime'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    outtime = new_today_date + ' ' + str(splitting[1])

                    temp['outgoingtime'] = outtime
                output.append(temp)
        output.reverse()
        return jsonify({'status': 1, 'message': 'Get security prebooking list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/get_resident_prebooking_list', methods=['POST'])
def get_resident_prebooking_list():
    coll = mongo.db.visitor_pre_bookings
    e_id = request.json['e_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    try:
        output = []
        for li in coll.find():
            temp = {}
            if li['e_id'] == e_id:
                temp['visitor_name'] = li['visitor_name']
                temp['community_id'] = li['community_id']
                temp['visitor_location'] = li['visitor_location']
                temp['visitor_mobile_number'] = li['visitor_mobile_number']
                temp['verify_status'] = li['verify_status']
                temp['select_time'] = li['select_time']
                if 'body_temperature' not in li.keys():
                    temp['body_temperature'] = ''
                else:
                    temp['body_temperature'] = li['body_temperature']
                temp['vehicle_type'] = li['vehicle_type']
                temp['date'] = li['date']
                if 'duration' not in li.keys():
                    temp['duration'] = ''
                else:
                    temp['duration'] = li['duration']
                temp['select_week'] = li['select_week']

                splitting = li['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime
                if 'outgoingtime' not in li.keys():
                    temp['outgoingtime'] = ''

                else:
                    splitting = li['outgoingtime'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    outtime = new_today_date + ' ' + str(splitting[1])

                    temp['outgoingtime'] = outtime
                output.append(temp)
        output.reverse()
        return jsonify({'status': 1, 'message': 'Get resident prebooking list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/get_security_accept_list', methods=['POST'])
def get_security_accept_list():
    coll = mongo.db.visitors
    sec_id = request.json['sec_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    try:
        output = []
        for li in coll.find({'sec_id': sec_id}):
            temp = {}
            if 'status' in li.keys():
                if li['status'] == 0:
                    temp['visitor_name'] = li['visiter_name']
                    # temp['company_id'] = li['company_id']
                    temp['visitor_location'] = li['visitor_location']
                    if 'body_temperature' not in li.keys():
                        temp['body_temperature'] = ''
                    else:
                        temp['body_temperature'] = li['body_temperature']
                    temp['mobile_number'] = li['mobile_number']

                    splitting = li['created_time'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    intime = new_today_date + ' ' + str(splitting[1])

                    temp['in_time'] = intime
                    temp['visit_id'] = li['visit_id']
                    if 'duration' not in li.keys():
                        temp['duration'] = ''
                    else:
                        temp['duration'] = li['duration']
                    if 'mask' not in li.keys():
                        temp['mask'] = 2
                    else:
                        temp['mask'] = li['mask']
                    # temp['duration'] = '25 min'
                    temp['user_pic'] = li['user_pic']
                    temp['whom_to_meet'] = li['whom_to_meet']
                    if 'outgoingtime' not in li.keys():
                        temp['outgoingtime'] = ''

                    else:
                        splitting = li['outgoingtime'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        outtime = new_today_date + ' ' + str(splitting[1])

                        temp['outgoingtime'] = outtime
                    output.append(temp)
        output.reverse()
        return jsonify({'status': 1, 'message': 'Get security accept list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/get_resident_accept_list', methods=['POST'])
def get_resident_accept_list():
    coll = mongo.db.visitors
    e_id = request.json['e_id']
    try:
        output = []
        for li in coll.find({'e_id': e_id}):
            temp = {}
            if 'status' in li.keys():
                if li['status'] == 0:
                    temp['visitor_name'] = li['visiter_name']
                    # temp['company_id'] = li['company_id']
                    temp['visitor_location'] = li['visitor_location']
                    temp['mobile_number'] = li['mobile_number']
                    temp['visit_id'] = li['visit_id']

                    splitting = li['created_time'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    intime = new_today_date + ' ' + str(splitting[1])

                    temp['in_time'] = intime
                    if 'duration' not in li.keys():
                        temp['duration'] = ''
                    else:
                        temp['duration'] = li['duration']
                    if 'mask' not in li.keys():
                        temp['mask'] = 2
                    else:
                        temp['mask'] = li['mask']
                    # temp['duration'] = '25 min'
                    if 'body_temperature' not in li.keys():
                        temp['body_temperature'] = ''
                    else:
                        temp['body_temperature'] = li['body_temperature']
                    temp['user_pic'] = li['user_pic']
                    temp['whom_to_meet'] = li['whom_to_meet']

                    if 'outgoingtime' not in li.keys():
                        temp['outgoingtime'] = ''

                    else:
                        splitting = li['outgoingtime'].split(' ')
                        date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                        new_today_date = date_time_obj.strftime("%d/%m/%Y")
                        outtime = new_today_date + ' ' + str(splitting[1])

                        temp['outgoingtime'] = outtime
                    output.append(temp)
        output.reverse()
        return jsonify({'status': 1, 'message': 'Get resident accept list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/get_resident_denied_list', methods=['POST'])
def get_resident_denied_list():
    coll = mongo.db.visitors
    e_id = request.json['e_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    try:
        output = []
        for li in coll.find({'e_id': e_id}):
            temp = {}
            if 'status' in li.keys():
                if li['status'] == 2:
                    temp['visitor_name'] = li['visiter_name']
                    # temp['company_id'] = li['company_id']
                    temp['visitor_location'] = li['visitor_location']
                    temp['mobile_number'] = li['mobile_number']

                    splitting = li['created_time'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    intime = new_today_date + ' ' + str(splitting[1])

                    temp['in_time'] = intime
                    temp['visit_id'] = li['visit_id']
                    # temp['duration'] = '25 min'
                    if 'body_temperature' not in li.keys():
                        temp['body_temperature'] = ''
                    else:
                        temp['body_temperature'] = li['body_temperature']
                    if 'mask' not in li.keys():
                        temp['mask'] = 2
                    else:
                        temp['mask'] = li['mask']
                    temp['user_pic'] = li['user_pic']
                    temp['whom_to_meet'] = li['whom_to_meet']
                    output.append(temp)
        output.reverse()
        return jsonify({'status': 1, 'message': 'Get resident denied list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/get_security_denied_list', methods=['POST'])
def get_security_denied_list():
    coll = mongo.db.visitors
    sec_id = request.json['sec_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    try:
        output = []
        for li in coll.find({'sec_id': sec_id}):
            temp = {}
            if 'status' in li.keys():
                if li['status'] == 2:
                    temp['visitor_name'] = li['visiter_name']
                    if 'body_temperature' not in li.keys():
                        temp['body_temperature'] = ''
                    else:
                        temp['body_temperature'] = li['body_temperature']

                    if 'mask' not in li.keys():
                        temp['mask'] = 2
                    else:
                        temp['mask'] = li['mask']
                    # temp['company_id'] = li['company_id']
                    temp['visitor_location'] = li['visitor_location']
                    temp['mobile_number'] = li['mobile_number']

                    splitting = li['created_time'].split(' ')
                    date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                    new_today_date = date_time_obj.strftime("%d/%m/%Y")
                    intime = new_today_date + ' ' + str(splitting[1])

                    temp['in_time'] = intime
                    temp['visit_id'] = li['visit_id']
                    temp['user_pic'] = li['user_pic']
                    temp['whom_to_meet'] = li['whom_to_meet']
                    output.append(temp)
        output.reverse()
        return jsonify({'status': 1, 'message': 'Get security denied list', 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/activity_screen_visitors_for_resident', methods=['POST'])
def activity_screen_visitors_for_resident():
    # coll=mongo.db.employee_users
    # coll1 = mongo.db.security_users
    coll2 = mongo.db.visitors
    coll3 = mongo.db.visitor_pre_bookings
    e_id = request.json['e_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    # details=coll2.find({'sec_id':sec_id})
    try:
        output = []
        for li in coll2.find({'e_id': e_id}):
            temp = {}
            temp['visitor_name'] = li['visiter_name']
            # temp['company_id'] = li['company_id']
            temp['visitor_location'] = li['visitor_location']
            temp['mobile_number'] = li['mobile_number']
            if 'body_temperature' not in li.keys():
                temp['body_temperature'] = ''
            else:
                temp['body_temperature'] = li['body_temperature']
            temp['visitor_mobile_number'] = ''

            splitting = li['created_time'].split(' ')
            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
            new_today_date = date_time_obj.strftime("%d/%m/%Y")
            intime = new_today_date + ' ' + str(splitting[1])

            temp['in_time'] = intime
            if 'duration' not in li.keys():
                temp['duration'] = ''
            else:
                temp['duration'] = li['duration']
            if 'mask' not in li.keys():
                temp['mask'] = 2
            else:
                temp['mask'] = li['mask']
            # temp['duration'] = '25 min'
            temp['user_pic'] = li['user_pic']
            temp['e_id'] = e_id
            temp['whom_to_meet'] = li['whom_to_meet']

            if 'outgoingtime' not in li.keys():
                temp['outgoingtime'] = ''

            else:
                splitting = li['outgoingtime'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                outtime = new_today_date + ' ' + str(splitting[1])

                temp['outgoingtime'] = outtime
            output.append(temp)

        for lv in coll3.find({'e_id': e_id}):
            temp = {}
            temp['visitor_name'] = lv['visitor_name']
            # temp['company_id'] = li['company_id']
            temp['visitor_location'] = lv['visitor_location']
            temp['visitor_mobile_number'] = lv['visitor_mobile_number']
            if 'body_temperature' not in lv.keys():
                temp['body_temperature'] = ''
            else:
                temp['body_temperature'] = lv['body_temperature']
            temp['mobile_number'] = ''

            splitting = lv['created_time'].split(' ')
            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
            new_today_date = date_time_obj.strftime("%d/%m/%Y")
            intime = new_today_date + ' ' + str(splitting[1])

            temp['in_time'] = intime
            # temp['duration'] = '25 min'
            temp['user_pic'] = ""
            temp['whom_to_meet'] = ""
            if 'duration' not in lv.keys():
                temp['duration'] = ''
            else:
                temp['duration'] = lv['duration']
            if 'mask' not in lv.keys():
                temp['mask'] = 2
            else:
                temp['mask'] = lv['mask']
            temp['e_id'] = e_id
            if 'outgoingtime' not in lv.keys():
                temp['outgoingtime'] = ''

            else:
                splitting = lv['outgoingtime'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                outtime = new_today_date + ' ' + str(splitting[1])

                temp['outgoingtime'] = outtime
            output.append(temp)
        output.reverse()
        finaloutput = {}
        finaloutput['status'] = 1
        # finaloutput['login_status'] = 1
        finaloutput['message'] = 'Get total visitors list for resident'
        finaloutput['result'] = output
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/activity_screen_visitors_for_security', methods=['POST'])
def activity_screen_visitors_for_security():
    # coll=mongo.db.employee_users
    # coll1 = mongo.db.security_users
    coll2 = mongo.db.visitors
    coll3 = mongo.db.visitor_pre_bookings
    sec_id = request.json['sec_id']
    # e_id=request.json['e_id']
    # company_id=request.json['company_id']
    # details=coll2.find({'sec_id':sec_id})
    try:
        output = []
        for li in coll2.find({'sec_id': sec_id}):
            temp = {}
            temp['visitor_name'] = li['visiter_name']
            # temp['company_id'] = li['company_id']
            temp['visitor_location'] = li['visitor_location']
            temp['mobile_number'] = li['mobile_number']
            if 'body_temperature' not in li.keys():
                temp['body_temperature'] = ''
            else:
                temp['body_temperature'] = li['body_temperature']
            temp['visitor_mobile_number'] = ''

            splitting = li['created_time'].split(' ')
            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
            new_today_date = date_time_obj.strftime("%d/%m/%Y")
            intime = new_today_date + ' ' + str(splitting[1])

            temp['in_time'] = intime
            # temp['duration'] = '25 min'
            if 'duration' not in li.keys():
                temp['duration'] = ''
            else:
                temp['duration'] = li['duration']
            if 'mask' not in li.keys():
                temp['mask'] = 2
            else:
                temp['mask'] = li['mask']
            temp['user_pic'] = li['user_pic']
            temp['sec_id'] = sec_id
            temp['whom_to_meet'] = li['whom_to_meet']

            if 'outgoingtime' not in li.keys():
                temp['outgoingtime'] = ''

            else:
                splitting = li['outgoingtime'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                outtime = new_today_date + ' ' + str(splitting[1])

                temp['outgoingtime'] = outtime

            output.append(temp)

        for lv in coll3.find({'sec_id': sec_id}):
            temp = {}
            temp['visitor_name'] = lv['visitor_name']
            # temp['company_id'] = li['company_id']
            temp['visitor_location'] = lv['visitor_location']
            temp['visitor_mobile_number'] = lv['visitor_mobile_number']
            if 'body_temperature' not in lv.keys():
                temp['body_temperature'] = ''
            else:
                temp['body_temperature'] = lv['body_temperature']
            if 'duration' not in lv.keys():
                temp['duration'] = ''
            else:
                temp['duration'] = lv['duration']

            if 'mask' not in lv.keys():
                temp['mask'] = 2
            else:
                temp['mask'] = lv['mask']

            temp['mobile_number'] = ""

            splitting = lv['created_time'].split(' ')
            date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
            new_today_date = date_time_obj.strftime("%d/%m/%Y")
            intime = new_today_date + ' ' + str(splitting[1])

            temp['in_time'] = intime
            # temp['duration'] = '25 min'
            temp['user_pic'] = ""
            temp['whom_to_meet'] = ""
            temp['sec_id'] = sec_id

            if 'outgoingtime' not in lv.keys():
                temp['outgoingtime'] = ''

            else:
                splitting = lv['outgoingtime'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                outtime = new_today_date + ' ' + str(splitting[1])

                temp['outgoingtime'] = outtime

            output.append(temp)
        output.reverse()
        finaloutput = {}
        finaloutput['status'] = 1
        # finaloutput['login_status'] = 1
        finaloutput['message'] = 'Get total visitors list for security'
        finaloutput['result'] = output
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


##########################################exit button ########################################
@app.route('/i_res/outgoingtime', methods=['POST'])
def outgoingtime():
    coll1 = mongo.db.resident_users
    coll2 = mongo.db.visitor_pre_bookings
    coll3 = mongo.db.visitors
    output = []
    try:
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        outgoingtime = now_asia.strftime('%Y/%m/%d %H:%M')
        try:
            visit_id = request.json['visit_id']
        except KeyError or ValueError:
            visit_id = 0
        try:
            id = request.json['id']
        except KeyError or ValueError:
            id = 0
        coll3.update({'visit_id': int(visit_id)}, {'$set': {'outgoingtime': outgoingtime}})
        coll2.update({'id': int(id)}, {'$set': {'outgoingtime': outgoingtime}})
        output.append({'outgoingtime': outgoingtime, 'visit_id': visit_id, "id": id})
        for data in coll2.find({'id': id}):
            for ls in coll1.find({'e_id': data['e_id']}):
                attention = data["visitor_name"] + " left the office"
                resident_push_notifications(attention, ls['device_token'], data['sec_id'], outgoingtime)
        for data in coll2.find({'visit_id': visit_id}):
            for ls in coll1.find({'e_id': data['e_id']}):
                attention = data["visiter_name"] + " left the office"
                resident_push_notifications(attention, ls['device_token'], data['sec_id'], outgoingtime)
        return jsonify({'status': 1, 'message': 'outgoing time updated successfully', 'result': output})
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


#######################################language list#########################################################

@app.route('/i_res/language_list', methods=['GET'])
def language_list():
    f = open('/var/www/html/ires/languages.txt', 'r')
    # if f.mode==r:
    content = f.read()
    output = json.loads(content)
    return jsonify({'status': 'success', 'message': "Language list", 'result': output})


############################################visitor verify otp ##############################################
@app.route('/i_res/verify_visitor_otp', methods=['POST'])
def verify_visitor_otp():
    try:
        # db = client.ipermit
        coll = mongo.db.visitor_pre_bookings
        coll2 = mongo.db.resident_users
        otp = str(request.json['otp'])
        id = request.json['id']
        created_time = strftime("%Y/%m/%d %H:%M")
        datetime_object = datetime.datetime.strptime(created_time, '%Y/%m/%d %H:%M')
        now_asia = datetime_object.astimezone(timezone('Asia/Kolkata'))
        current_dt = now_asia.strftime('%Y/%m/%d %H:%M')
        output = []
        details = coll.find({'id': id})
        for data in details:
            if data['otp'] == otp:
                coll.update({'id': id}, {"$set": {'created_time': current_dt, 'verify_status': True}})
                output.append({'created_time': current_dt, 'id': id, 'otp': otp, 'verify_status': True})
                for ls in coll2.find({'e_id': data['e_id']}):
                    attention = data["visitor_name"] + " entered the office"
                    resident_push_notifications(attention, ls['device_token'], data['sec_id'], current_dt)
        finaloutput = {}
        if len(output) != 0:
            finaloutput['status'] = 1
            finaloutput['message'] = 'Otp verified successfully'
            finaloutput['result'] = output
        else:
            finaloutput['status'] = 0
            finaloutput['message'] = 'Invalid OTP. Please check and try again'
            # finaloutput['result'] = []
        return jsonify(finaloutput)
    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


################################################admin login ##############################################
@app.route('/i_res/admin_login', methods=['POST'])
def admin_login():
    username = request.json['username']
    password = request.json['password']
    try:
        if username == "admin" and password == "admin@123":
            return jsonify({'status': 1, 'message': 'Admin login Successfull'})

        return jsonify({'status': 0, 'message': 'Admin login Failed. Please try again'})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/search', methods=['GET', 'POST'])
# @cross_origin()
def search():
    try:
        coll = mongo.db.visitor_pre_bookings
        coll1 = mongo.db.visitors
        number = request.json['number']
        output = []
        for li in coll.find({'visitor_mobile_number': {'$regex': re.compile(number)}}):
            temp = {}
            temp['community_id'] = li['community_id']
            temp['e_id'] = li['e_id']
            temp['vehicle_type'] = li['vehicle_type']
            temp['otp'] = li['otp']
            temp['visitor_type'] = li['visitor_type']
            temp['visitor_mobile_number'] = li['visitor_mobile_number']
            temp['vehicle_number'] = li['vehicle_number']
            temp['date'] = li['date']
            temp['sec_id'] = li['sec_id']
            temp['select_time'] = li['select_time']
            temp['visitor_name'] = li['visitor_name']
            temp['visitor_location'] = li['visitor_location']
            temp['select_week'] = li['select_week']
            temp['id'] = li['id']
            if 'body_temperature' not in li.keys():
                temp['body_temperature'] = ''
            else:
                temp['body_temperature'] = li['body_temperature']
            if 'verify_status' not in li.keys():
                temp['verify_status'] = ""
            else:
                temp['verify_status'] = li['verify_status']
            if 'created_time' not in li.keys():
                temp['in_time'] = ""
            else:
                splitting = li['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime

            if 'outgoingtime' not in li.keys():
                temp['outgoingtime'] = ""
            else:
                splitting = li['outgoingtime'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                outtime = new_today_date + ' ' + str(splitting[1])

                temp['outgoingtime'] = outtime

            if 'duration' not in li.keys():
                temp['duration'] = ""
            else:
                temp['duration'] = li['duration']
            output.append(temp)
        for lv in coll1.find({'mobile_number': {'$regex': re.compile(number)}}):
            temp = {}
            temp['block_number'] = lv['block_number']
            temp['sec_id'] = lv['sec_id']
            temp['visiter_name'] = lv['visiter_name']

            temp['community_id'] = lv['community_id']

            temp['e_id'] = lv['e_id']
            temp['visit_id'] = lv['visit_id']
            temp['mobile_number'] = lv['mobile_number']
            temp['visitor_location'] = lv['visitor_location']
            if 'body_temperature' not in lv.keys():
                temp['body_temperature'] = ''
            else:
                temp['body_temperature'] = lv['body_temperature']
            if 'verify_status' not in lv.keys():
                temp['verify_status'] = ""
            else:
                temp['verify_status'] = lv['verify_status']
            if 'created_time' not in lv.keys():
                temp['in_time'] = ""
            else:
                splitting = lv['created_time'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                intime = new_today_date + ' ' + str(splitting[1])

                temp['in_time'] = intime

            if 'outgoingtime' not in lv.keys():
                temp['outgoingtime'] = ""
            else:
                splitting = lv['outgoingtime'].split(' ')
                date_time_obj = datetime.datetime.strptime(splitting[0], '%Y/%m/%d')
                new_today_date = date_time_obj.strftime("%d/%m/%Y")
                outtime = new_today_date + ' ' + str(splitting[1])

                temp['outgoingtime'] = outtime

            if 'duration' not in lv.keys():
                temp['duration'] = ""
            else:
                temp['duration'] = lv['duration']
            output.append(temp)
        return jsonify({'status': 1, 'message': 'Search', 'results': output})
    except Exception as e:
        return jsonify(status=0, message=str(e))



@app.route('/i_res/resident_details_list', methods=['GET'])
def resident_details_list():
    coll = mongo.db.resident_users
    output=[]
    try:
        for lst in coll.find():
            temp={}
            temp['flat_number']=lst['flat_number']
            temp['block_number']=lst['block_number']
            temp['resident_name']=lst['name']
            temp['e_id']=lst['e_id']
            output.append(temp)
        return jsonify({'status': 1, 'result': output})

    except Exception as e:
        return jsonify({'status': 0, 'message': str(e)})


@app.route('/i_res/validate_time', methods=['GET', 'POST'])
def validate_time():
    try:
        select_time = request.json['select_time']
        FMT = '%H:%M'
        splitting_time = select_time.split('-')
        start_time = splitting_time[0]
        end_time = splitting_time[1]
        if datetime.datetime.strptime(start_time, FMT) == datetime.datetime.strptime(end_time,
                                                                                     FMT) or datetime.datetime.strptime(
                start_time, FMT) > datetime.datetime.strptime(end_time, FMT):
            return jsonify({'status': 0, 'message': 'To time should be greater than From Time'})
        return jsonify({'status': 1, 'message': 'validation successfull'})

    except Exception as e:
        return jsonify(status=0, message=str(e))


@app.route('/i_res/version', methods=['GET', 'POST'])
def version():
    try:
        versions = '1.0'
        version = request.json['version']
        if version != versions:
            return jsonify({'status': 0, 'message': 'Please update'})
        return jsonify({'status': 1, 'message': 'success'})
    except Exception as e:
        return jsonify(status=0, message=str(e))


if __name__ == '__main__':
    # app.run(debug=True)
    app.run(host='0.0.0.0', port=9000, debug=True, threaded=True)
