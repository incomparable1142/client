from flask import Flask, request, make_response, render_template, jsonify,\
                    session, url_for, redirect
from uuid import getnode as get_mac
import uuid
from flask.ext.bcrypt import Bcrypt
import time
from datetime import datetime, timedelta
import jwt
import os
import datetime
from functools import wraps
import traceback
from db import Mdb
from wtforms.fields import SelectField
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import json
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
from bson.objectid import ObjectId

app = Flask(__name__, static_path='/static')
bcrypt = Bcrypt(app)
mdb = Mdb()

app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


#############################################
#                                           #
#        _id of mongodb record was not      #
#           getting JSON encoded, so        #
#           using this custom one           #
#                                           #
#############################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#           Login Manager                    #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


##############################################
#               get mac address              #
##############################################
# @app.route('/mac')
def get_mac():
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac = '-'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
    return mac


@app.route('/check')
@login_required
def check():
    return "checking"


@app.route('/admin')
def admin():
    templateData = {'title': 'index page'}
    return render_template('admin/index.html', **templateData)


@app.route('/user')
def home():
    templateData = {'title': 'Login Page'}
    return render_template('user/index.html', session=session)


@app.route('/whoami')
def whoami():
    ret = {'error': 0}
    try:
        sumSessionCounter()
        ret['User'] = (" hii i am %s !!" % session['name'])
    except Exception as exp:
        ret['error'] = 1
        ret['user'] = 'user is not login'
    return json.dumps(ret)


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})

        return f(*args, **kwargs)

    return decorated


# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #
#                                           #
#        NOT USING THIS AT THE MOMENT       #
#                                           #
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #
@app.route('/login_old')
def login_old():
    auth = request.authorization

    if auth and auth.password == 'password':
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'user': auth.username, 'exp': expiry},
                           app.config['secretkey'], algorithm='HS256')
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify!', 401,
                         {'WWW-Authenticate': 'Basic realm="Login Required"'})


#############################################
#                                           #
#                   ADD FORM                #
#                                           #
#############################################
@app.route("/user_form", methods=['POST'])
def user_form():
    try:
        user_id = request.form['user_id']
        key = request.form['key']
        value = request.form['value']
        mdb.user_form(user_id, key, value)
        print('User form is added successfully')
        templateData = {'title': 'form Page'}
    except Exception as exp:
        print('User form() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return render_template('form.html', session=session)


##############################################################################
#                                                                            #
#                                    ADMIN PANNEL                            #
#                                                                            #
##############################################################################
#############################################
#                 LOGIN ADMIN               #
#############################################
@app.route('/admin/admin_login', methods=['POST'])
def admin_login():
    ret = {'err': 0}
    try:

        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.admin_exists(email, password):
            name = mdb.get_name(email)
            session['name'] = name

            expiry = datetime.datetime.utcnow() + datetime.\
                timedelta(minutes=30)
            token = jwt.encode({'user': email, 'exp': expiry},
                               app.config['secretkey'], algorithm='HS256')
            ret['msg'] = 'Login successful'
            ret['err'] = 0
            ret['token'] = token.decode('UTF-8')
            return render_template('admin/index.html', session=session)
        else:
            templateData = {'title': 'singin page'}
            # Login Failed!
            return render_template('/admin/index.html', session=session)
            # return "Login faild"
            ret['msg'] = 'Login Failed'
            ret['err'] = 1

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
        # return jsonify(ret)
        return render_template('admin/index.html', session=session)


##############################################################################
#                                                                            #
#                                APIs                                        #
#                                                                            #
##############################################################################
@app.route('/app/get_responses',methods = ['GET'])
def get_responses_api():
    responses = mdb.get_responses()
    return JSONEncoder().encode({'responses': responses})\


@app.route('/app/get_surveys',methods = ['GET'])
def get_surveys_api():
    surveys = mdb.get_surveys()
    return JSONEncoder().encode({'surveys': surveys})


@app.route('/app/get_session',methods = ['GET'])
def get_session_api():
    session = mdb.get_sessions()
    return JSONEncoder().encode({'session': session})


#############################################
#                  GET RESPONSE             #
#############################################
@app.route("/admin/get_responses", methods=['GET'])
def get_responses_admin():
    responses = mdb.get_responses()
    templateData = {'title': 'Responces', 'responses': responses}
    return render_template('admin/get_responses.html', **templateData)


#############################################
#                GET SURVEY                 #
#############################################
@app.route("/admin/get_surveys", methods=['GET'])
def get_surveys_admin():
    surveys = mdb.get_surveys()
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('admin/get_survey.html', **templateData)


############################################################################
#                                                                          #
#                                     USER PANNEL                          #
#                                                                          #
############################################################################
#############################################
#                  ADD USER                 #
#############################################
@app.route('/user/signup')
def signin():
    templateData = {'title': 'Signup .Page'}
    return render_template('user/signup.html', session=session)


@app.route("/user/add_user", methods=['POST'])
def add_user():
    try:
        user = request.form['user']
        contact = request.form['contact']
        email = request.form['email']
        password = request.form['password']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        mdb.add_user(user, contact, email, pw_hash)
        print('User is added successfully')
        templateData = {'title': 'Signin Page'}
    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return render_template('user/index.html', session=session)


#############################################
#                 LOGIN USER                #
#############################################
@app.route('/login', methods=['POST'])
def login():

    ret = {'err': 0}

    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print 'password in server, get from db class', pw_hash
            passw = bcrypt.check_password_hash(pw_hash, password)

            print 'get status=======================', passw

            if passw == True:

                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email
                # print "==========", session['email']
                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)
                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')

                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
                templateData = {'title': 'singin page'}
            else:
                return render_template('user/index.html', session=session)

        else:
            # Login Failed!
            return render_template('user/index.html', session=session)

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

        LOGIN_TYPE = 'User Login'
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr

        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    # return jsonify(ret)
    return render_template('user/index.html', session=session)


#############################################
#               CREATE SURVEY               #
#############################################
@app.route('/user/create_survey')
def survey():
    templateData = {'title': 'create_survey'}
    return render_template('user/create_survey.html', session=session)


#############################################
#               CREATE RESPONSE             #
#############################################
@app.route("/user/create_response", methods=['GET'])
def create_response():
    id = request.args.get("id")
    survey = mdb.get_survey(id)
    responses = mdb.get_responses_by_id(id)
    templateData = {'title': 'Survey Response', 'survey': survey, 'responses': responses}
    return render_template('user/create_response.html', **templateData)


#############################################
#                SAVE SURVEY                #
#############################################
@app.route("/user/save_survey", methods=['POST'])
def save_survey():

    # survery dictionary to be saved in db
    survey = {}

    try:

        title = request.form['title']
        rowCount = int(request.form['rowCount'])
        ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
        email = session['email']

        survey['title'] = title
        survey['rowCount'] = rowCount
        survey['session_id'] = email
        survey['TimeStamp'] = ts

        # adding all keys/values in form dict
        for i in range(1, rowCount+1):
            print "Reading Key%d" % i
            try:
                survey['ques_id%d' % i] = rowCount = request.form['key%d' % i]
                survey['ques_description%d' % i] = rowCount = \
                    request.form['value%d' % i]
                survey['type%d' % i] = rowCount = request.form['type%d' % i]
            except:
                print "Key%d not  found" % i
        print "survey: ", survey

        # saving survey in db
        mdb.add_survey(survey)

        # return "Survery Saved"
        return render_template('user/save_survey.html', session=session)

    except Exception as exp:
        print(traceback.format_exc())
        return "Failed to Save Survery, Exception: %s" % exp


#############################################
#               SAVE RESPONSE               #
#############################################
@app.route('/user/save_response', methods=['POST'])
def save_response():
    response = {}
    try:
        # user = request.form['user']
        survey_id = request.form['survey_id']
        title = request.form['survey_title']
        ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
        rowCount = int(request.form['rowCount'])

        email = session['email']
        # response['user'] = user
        response['survey_id'] = survey_id
        response['title'] = title
        response['rowCount'] = rowCount
        response['timeStamp'] = ts
        response['Session_email'] = email

        for i in range(1, (rowCount+1)):

            print "Reading Key%d" % i
            try:
                response['ques_description%d' % i] = \
                    request.form['value%d' % i]
            except:
                print "Key%d not  found" % i

        mdb.save_response(response)
    except Exception as exp:
        print('save_response() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return render_template('user/save_response.html', session=session)


#############################################
#                GET SURVEY                 #
#############################################
@app.route("/user/get_surveys", methods=['GET'])
def get_surveys():
    surveys = mdb.get_surveys()
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('user/get_survey.html', **templateData)


#############################################
#               SURVEY RESPONSE             #
#############################################
@app.route("/user/get_responses", methods=['GET'])
def get_responses():
    responses = mdb.get_responses()
    templateData = {'title': 'Responces', 'responses': responses}
    return render_template('user/get_responses.html', **templateData)


#############################################
#              FORGOT PASSWORD              #
#############################################
@app.route('/forgot')
def forgot():
    templateData = {'title': 'forgot password'}
    return render_template('user/forgot.html', session=session)


#############################################
#              FORGOT PASSWORD              #
#############################################
@app.route('/user/contact')
def contact():
    templateData = {'title': 'forgot password'}
    return render_template('user/contact.html', session=session)


#############################################
#                GET PASSWORD                 #
#############################################
@app.route("/user/forgot_password", methods=['POST'])
def get_password():
    email = request.form['email']
    password = mdb.get_password(email)
    passw = bcrypt.check_password_hash(pw_hash, password)
    # templateData = {'title': 'password', 'password': password}
    # return render_template('user/get_survey.html', **templateData)
    print"=====================", password
    return "hiiiii"


#############################################
#              SESSION LOGOUT               #
#############################################
@app.route('/clear')
def clearsession():
    try:
        LOGIN_TYPE = 'User Logout'
        sumSessionCounter()
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        return render_template('user/index.html', session=session)
    except Exception as exp:
        return 'clearsession() :: Got Exception: %s' % exp


###########################################
#          session logout admin           #
###########################################
@app.route('/clear1')
def clearsession1():
    session.clear()
    return render_template('/admin/index.html', session=session)
    # return redirect(request.form('/signin'))


@app.route('/get_info')
def get_info():
    try:
        LOGIN_TYPE = 'User Login'
        sumSessionCounter()
        email = session['email']
        user_email = email
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')

        mdb.save_login_info(user_email, ip, agent, LOGIN_TYPE)
        return 'User_email: %s, IP: %s, ' \
               'User-Agent: %s' % (user_email, ip, agent, LOGIN_TYPE)
    except Exception as exp:
        print('get_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return ('get_info() :: Got exception: %s is '
                'not found Please Login first' % exp)


#############################################
#                                           #
#                  MAIN SERVER              #
#                                           #
#############################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
