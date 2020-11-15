
"""
Columbia's COMS W4111.001 Introduction to Databases
Example Webserver
To run locally:
    python server.py
Go to http://localhost:8111 in your browser.
A debugger such as "pdb" may be helpful for debugging.
Read about it online.
"""
import os
  # accessible as a variable in index.html:
from sqlalchemy import *
from sqlalchemy.pool import NullPool
from flask import Flask, request, render_template, g, redirect, Response, jsonify, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from hashlib import sha256
from werkzeug.security import safe_str_cmp

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=tmpl_dir)

DATABASEURI = "postgresql://al4008:0475@34.75.150.200/proj1part2"

engine = create_engine(DATABASEURI)

# JWT/Authentication stuff
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


@app.before_request
def before_request():
  """
  This function is run at the beginning of every web request 
  (every time you enter an address in the web browser).
  We use it to setup a database connection that can be used throughout the request.

  The variable g is globally accessible.
  """
  try:
    g.conn = engine.connect()
  except:
    print("uh oh, problem connecting to database")
    import traceback; traceback.print_exc()
    g.conn = None


@app.teardown_request
def teardown_request(exception):
  """
  At the end of the web request, this makes sure to close the database connection.
  If you don't, the database could run out of memory!
  """
  try:
    g.conn.close()
  except Exception as e:
    pass


@app.route('/')
def index():
  """
  request is a special object that Flask provides to access web request information:

  request.method:   "GET" or "POST"
  request.form:     if the browser submitted a form, this contains the data in the form
  request.args:     dictionary of URL arguments, e.g., {a:1, b:2} for http://localhost?a=1&b=2

  See its API: http://flask.pocoo.org/docs/0.10/api/#incoming-request-data
  """

  return 'root'


@app.route('/signup', methods=['GET', 'POST'])
def signup():
  if request.method == 'GET':
    return render_template('signup.html')

  email = request.form['email']
  password = request.form['password']

  if not email:
    return jsonify({'msg': 'Missing email parameter. Go back and try again'}), 400
  if not password:
    return jsonify({'msg': 'Missing password parameter. Go back and try again'}), 400

  hashedPassword = sha256(password.encode('utf-8')).hexdigest()
  try:
    g.conn.execute('INSERT INTO users(email, hashed_pwd) VALUES (%s, %s)', email, hashedPassword)
  except:
    return jsonify({'msg': 'Failed to create new account'})

  access_token = create_access_token(identity=email)
  return redirect('http://localhost:8111/success?access_token=' + access_token), 200


@app.route('/debug')
def debug():
  site = ''
  cursor = g.conn.execute('SELECT * FROM users')
  for res in cursor:
    site += res['email'] + ', ' + res['hashed_pwd'] + '\r\n'

  return site


@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'GET':
    return render_template('login.html')

  email = request.form['email']
  password = request.form['password']

  if not email:
    return jsonify({'msg': 'Missing email parameter. Go back and try again'}), 400
  if not password:
    return jsonify({'msg': 'Missing password parameter. Go back and try again'}), 400

  # TODO: Proper validation
  if email != 'a@gmail.com':
      return jsonify({"msg": "Invalid email or password. Go back and try again"}), 401

  access_token = create_access_token(identity=email)
  return redirect('/success?access_token=' + access_token), 200


@app.route('/success', methods=['GET'])
def success():
  return render_template('success.html')


@app.route('/pantry', methods=['GET'])
def pantry():
  return render_template('pantry-blank.html')


@app.route('/pantry-loaded', methods=['GET'])
@jwt_required
def pantry_loaded():
  return '<h1>We did it!</h1>'


if __name__ == "__main__":
  import click

  @click.command()
  @click.option('--debug', is_flag=True)
  @click.option('--threaded', is_flag=True)
  @click.argument('HOST', default='0.0.0.0')
  @click.argument('PORT', default=8111, type=int)
  def run(debug, threaded, host, port):
    """
    This function handles command line parameters.
    Run the server using:

        python server.py

    Show the help text using:

        python server.py --help

    """

    HOST, PORT = host, port
    print("running on %s:%d" % (HOST, PORT))
    app.run(host=HOST, port=PORT, debug=debug, threaded=threaded)

  run()
