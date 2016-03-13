# api_ed_ws.py
#
# Responsible for handling HTTP requests, implementing pages of the api_ed web site.
# Uses the 'Flask' framework to bind web site page paths to handler methods, bind
# python object to HTML templates to render dynamic content.
from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, make_response
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from orm import Base, User, Parameter, RestCall, db_connection_info

from flask import session as login_session
import random
import string

APPLICATION_NAME = "API Editor Website"
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"    # still using this name from the class example


#Connect to Database and create database session
engine = create_engine(db_connection_info)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#Show all REST calls
@app.route('/')
@app.route('/api/all')
def showRestCalls():
  restCalls = session.query(RestCall).order_by(asc(RestCall.path))
  print('rendering restCalls.html')
  return render_template('restCalls.html', restCalls = restCalls)

# Create unforgeable state token
@app.route('/login')
def showLogin():
    # # mock valid login by setting user_id in login session and showRestCalls...
    # print('faking login with hard coded user_id=0')
    # login_session['user_id'] = 0
    # return showRestCalls()

    #here is the code we should execute when it's working
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

#GET form to edit a new REST call, POST form data to create it.
@app.route('/api/create', methods=['GET','POST'])
def createRestCall():
  if 'user_id' not in login_session:
    return redirect('/login')
  if request.method == 'GET':
    return render_template('newRestCall.html')
  else:
    restCall = RestCall(method= request.form['method'], path=request.form['path'], user_id=login_session['user_id'])
    session.add(restCall)
    session.commit()
    flash('Successfully Created %s' % restCall.__repr__())
    return redirect(url_for('showRestCalls'))

#GET all detail of RestCall
@app.route('/api/<int:call_id>')
def showRestCallDetail(call_id):
  restCall = session.query(RestCall).filter_by(id = call_id).one()
  if 'user_id' in login_session and restCall.user_id == login_session['user_id']:
    html = 'protectedRestCallDetail.html'
  else:
    html = 'protectedRestCallDetail.html'
  return render_template(html, restCall = restCall)

#GET form to edit a REST call, POST form data to update it.
@app.route('/api/<int:call_id>/edit/', methods = ['GET', 'POST'])
def editRestCall(call_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  restCall = session.query(RestCall).filter_by(id = call_id).one()
  if request.method == 'GET':
    return render_template('editRestCall.html', restCall = restCall)
  else:
    if request.form['method']:
      restCall.method = request.form['method']
    if request.form['path']:
      restCall.path = request.form['path']
    flash('Successfully Edited %s' % restCall.__repr__())
    return redirect(url_for('showRestCallDetail', call_id = restCall.id))

#GET form to delete a REST call, POST form data to perform the delete.
@app.route('/api/<int:call_id>/delete/', methods = ['GET','POST'])
def deleteRestCall(call_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  restCall = session.query(RestCall).filter_by(id = call_id).one()
  if request.method == 'GET':
    return render_template('deleteRestCall.html', restCall = restCall)
  else:
    session.delete(restCall)
    session.commit()
    flash('%s Successfully Deleted' % restCall.name())
    return redirect(url_for('showRestCalls'))

#GET form to edit a REST call DESCRIPTION, POST form data to update it.
@app.route('/api/<int:call_id>/editDescription', methods = ['GET', 'POST'])
def editDescription(call_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  restCall = session.query(RestCall).filter_by(id = call_id).one()
  if request.method == 'GET':
    return render_template('editDescription.html', restCall = restCall)
  else:
    if request.form['description']:
      restCall.description = request.form['description']
    return redirect(url_for('showRestCallDetail', call_id = restCall.id))

#GET form to edit a REST call EXAMPLE REQUEST, POST form data to update it.
@app.route('/api/<int:call_id>/editExampleRequest', methods = ['GET', 'POST'])
def editExampleRequest(call_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  restCall = session.query(RestCall).filter_by(id = call_id).one()
  if request.method == 'GET':
    return render_template('editExampleRequest.html', restCall = restCall)
  else:
    if request.form['exampleRequest']:
      restCall.exampleRequest = request.form['exampleRequest']
    return redirect(url_for('showRestCallDetail', call_id = restCall.id))

#GET form to edit a REST call EXAMPLE RESPONSE, POST form data to update it.
@app.route('/api/<int:call_id>/editExampleResponse', methods = ['GET', 'POST'])
def editExampleResponse(call_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  restCall = session.query(RestCall).filter_by(id = call_id).one()
  if request.method == 'GET':
    return render_template('editExampleResponse.html', restCall = restCall)
  else:
    if request.form['exampleResponse']:
      restCall.exampleResponse = request.form['exampleResponse']
    return redirect(url_for('showRestCallDetail', call_id = restCall.id))

#GET form to edit a new REST call PARAMETER, POST form data to create it.
@app.route('/api/<int:call_id>/createParameter', methods=['GET','POST'])
def createParameter(call_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  if request.method == 'GET':
    return render_template('newParameter.html')
  else:
    print('adding parameter to rest call')
    restCall = session.query(RestCall).filter_by(id = call_id).one()
    parameter = Parameter(restCall, None, None, None, None, None, None)
    if request.form['type']:
        parameter.type = request.form['type']
    if request.form['name']:
        parameter.name = request.form['name']
    if request.form['range']:
        parameter.range = request.form['range']
    if request.form['description']:
        parameter.description = request.form['description']
    if request.form['required']:
        if request.form['required'] == 'Y':
          parameter.required = True
        else:
          parameter.required = False
    if request.form['default']:
        parameter.default = request.form['default']
    restCall.parameters.append(parameter)
    session.commit()
    return redirect(url_for('showRestCallDetail', call_id = restCall.id))

#GET form to edit a REST call PARAMETER, POST form data to update it.
@app.route('/api/<int:call_id>/parameter/<int:parameter_id>/edit', methods = ['GET', 'POST'])
def editParameter(call_id, parameter_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  parameter = session.query(Parameter).filter_by(id = parameter_id).one()
  if request.method == 'GET':
    return render_template('editParameter.html', call_id = call_id, parameter = parameter)
  else:
    if request.form['type']:
      parameter.type = request.form['type']
    if request.form['name']:
      parameter.name = request.form['name']
    if request.form['range']:
      parameter.range = request.form['range']
    if request.form['description']:
      parameter.description = request.form['description']
    return redirect(url_for('showRestCallDetail', call_id = call_id))

#GET form to delete a REST call PARAMETER, POST form data to perform the delete.
@app.route('/api/<int:call_id>/parameter/<int:parameter_id>/delete', methods = ['GET','POST'])
def deleteParameter(call_id, parameter_id):
  if 'user_id' not in login_session:
    return redirect('/login')
  parameter = session.query(Parameter).filter_by(id = parameter_id).one()
  if request.method == 'GET':
    return render_template('deleteParameter.html', call_id = call_id, parameter = parameter)
  else:
    session.delete(parameter)
    session.commit()
    return redirect(url_for('showRestCallDetail', call_id = call_id))

def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user
    except:
        return None

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    print "getting state"
    if request.args.get('state') != login_session['state']:
        print "did not get state"
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    print "authorization code is "+code

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    print(login_session)
    print('does that tell you what type of object login_session is?')
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    print "storing new credentials from google login"
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    print "done storing new credentials from google login"

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # if user not yet in DB, create from login session info
    user_id = getUserID(login_session['email']) 
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    # flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token'] 
        del login_session['user_id']
        del login_session['gplus_id']
        del login_session['username']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
    
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response



if __name__ == '__main__':
  app.secret_key = 'vashon_dolphin'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
