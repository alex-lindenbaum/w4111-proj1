
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
import functools
from sqlalchemy import *
from sqlalchemy.pool import NullPool
from flask import Flask, request, render_template, g, redirect, Response, jsonify, url_for, flash, session
from hashlib import sha256
from werkzeug.security import safe_str_cmp
from datetime import date, timedelta

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=tmpl_dir)
app.config.from_mapping(
        SECRET_KEY='dev')

DATABASEURI = "database-uri"

engine = create_engine(DATABASEURI)


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

  return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
  if request.method == 'POST':
    email = request.form['email']
    password = request.form['password']
    error = None

    if not email:
      error = 'Missing email parameter. Try again.'
    if not password:
      error = 'Missing password parameter. Try again.'

    hashedPassword = sha256(password.encode('utf-8')).hexdigest()
    try:
      g.conn.execute('INSERT INTO users(email, hashed_pwd) VALUES (%s, %s)', email, hashedPassword)
    except:
      error = 'User already exists'

    if error is None:
      session.clear()
      session['user_id'] = email
      return redirect(url_for('dashboard'))
    flash(error)

  return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    email = request.form['email']
    password = request.form['password']
    error = None

    if not email:
      error = 'Missing email parameter. Try again.'
    elif not password:
      error = 'Missing password parameter. Try again.'
    else:
      user = g.conn.execute('SELECT * FROM users WHERE email = %s', email).fetchone()
      if user is None:
          error ='Invalid email'
      else:
        hashedpwd = sha256(password.encode('utf-8')).hexdigest()
        if not safe_str_cmp(hashedpwd, user['hashed_pwd']):
          error = 'Invalid password'
      
    if error is None:
      session.clear()
      session['user_id'] = email
      return redirect(url_for('dashboard'))

    flash(error)

  return render_template('login.html')


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = g.conn.execute(
            'SELECT * FROM users WHERE email = %s', user_id
        ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))

        return view(**kwargs)

    return wrapped_view

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
  return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/pantry', methods=['GET'])
@login_required
def pantry():
  email = g.user['email']
  cursor = g.conn.execute('SELECT storage_id, food_name, amount, unit, date_bought, shelf_life FROM storage_details \
    NATURAL JOIN food_items WHERE email = %s', email)
  today = date.today()
  return render_template('pantry.html', cursor=cursor, today=today, timedelta=timedelta)

@app.route('/additem', methods=['GET', 'POST'])
@login_required
def additem():
  if request.method == 'POST':
    food_name = request.form['food_name']
    amount = request.form['amount']
    unit = request.form['unit']
    date_bought = request.form['date_bought']
    email = g.user['email']

    error = None
    try:
      g.conn.execute('INSERT INTO storage_details(email, amount, unit, date_bought, food_name) \
        VALUES (%s, %s, %s, %s, %s)', email, amount, unit, date_bought, food_name)
    except:
      error = "Entry failed"
    if error is None:
      flash("Item added!")
      return redirect(url_for('additem'))

    flash(error)

  cursor = g.conn.execute('SELECT food_name FROM food_items')
  return render_template('additem.html', cursor=cursor)

@app.route('/pantry/update/<int:storage_id>', methods=['GET', 'POST'])
@login_required
def updateitem(storage_id):
  if request.method == 'POST':
    food_name = request.form['food_name']
    amount = request.form['amount']
    unit = request.form['unit']
    date_bought = request.form['date_bought']

    error=None
    try:
      g.conn.execute('UPDATE storage_details SET food_name = %s, amount = %s, unit = %s, date_bought = %s \
        WHERE storage_id = %s', food_name, amount, unit, date_bought, storage_id)
    except:
      error = "Entry failed"
    if error is None:
      flash("Item updated!")
      return redirect(url_for('pantry'))
    
    flash(error)

  cursor = g.conn.execute('SELECT food_name FROM food_items')
  item = g.conn.execute('SELECT storage_id, food_name, amount, unit, date_bought \
    FROM storage_details WHERE storage_id = %s', storage_id).fetchone()
  return render_template('updateitem.html', cursor=cursor, item=item)


@app.route('/pantry/delete/<int:storage_id>', methods=['POST'])
@login_required
def deleteitem(storage_id):
  g.conn.execute('DELETE FROM storage_details WHERE storage_id = %s', storage_id)
  return redirect(url_for('pantry'))

@app.route('/recipes', methods=['GET'])
@login_required
def recipes():
  email = g.user['email']

  liked_recipes = g.conn.execute('SELECT R.recipe_name, R.photo_url, R.url \
    FROM recipes R NATURAL JOIN has_impression H \
    WHERE H.email = %s AND H.liked', email)

  other_recipes =  g.conn.execute('SELECT R.recipe_name, R.photo_url, R.url \
    FROM recipes R \
    WHERE (SELECT COUNT(DISTINCT IR.food_name) FROM in_recipe IR INNER JOIN storage_details SD ON IR.food_name=SD.food_name \
                    WHERE SD.email = %s AND IR.url = R.url) > 1 \
    INTERSECT \
    SELECT R2.recipe_name, R2.photo_url, R2.url \
    FROM recipes R2 \
      WHERE NOT EXISTS (SELECT * FROM has_impression H \
                WHERE H.url = R2.url AND H.email = %s)', email, email)

  #shows all if user has no restrictions
  if g.conn.execute('SELECT * FROM has_restriction WHERE email=%s', email).fetchone() == None:
    diet_recipes = g.conn.execute('SELECT recipe_name, photo_url, url FROM recipes')
  else:
    diet_recipes = g.conn.execute('SELECT R.recipe_name, R.photo_url, R.url \
      FROM recipes R, has_restriction HR, fulfills_restriction FR \
      WHERE HR.email = %s AND FR.url = R.url AND HR.diet_name = FR.diet_name', email)
  
  return render_template('recipes.html', liked_recipes=liked_recipes, other_recipes=other_recipes, diet_recipes=diet_recipes)

@app.route('/recipes/dislike/<path:url>', methods=['POST'])
@login_required
def dislike_recipe(url):
  g.conn.execute('INSERT INTO has_impression(email, url, liked) VALUES (%s, %s, false)', g.user['email'], url)
  return redirect(url_for('recipes'))


@app.route('/recipes/like/<path:url>', methods=['POST'])
@login_required
def like_recipe(url):
  g.conn.execute('INSERT INTO has_impression (email, url, liked) VALUES (%s, %s, true)', g.user['email'], url)

  return redirect(url_for('recipes'))


@app.route('/recipes/unlike/<path:url>', methods=['POST'])
@login_required
def unlike_recipe(url):
  g.conn.execute('DELETE FROM has_impression WHERE email = %s AND url = %s', g.user['email'], url)

  return redirect(url_for('recipes'))

#TODO: add popular recipes
@app.route('/popularrecipes')
def popularrecipes():
  cursor = g.conn.execute('SELECT url, recipe_name, photo_url FROM recipes R \
    ORDER BY (SELECT COUNT(*) FROM has_impression HI WHERE HI.url=R.url AND liked) DESC LIMIT 10')
  return render_template('popularrecipes.html', cursor=cursor)

@app.route('/restrictions', methods=['GET', 'POST'])
@login_required
def restrictions():
  email = g.user['email']

  if request.method == 'POST':
    diet_name = request.form['diet_name']

    error = None
    try:
      g.conn.execute('INSERT INTO has_restriction(email, diet_name) VALUES (%s, %s)', email, diet_name)
    except:
      error = "Entry failed"
    if error is None:
      flash("Restriction added!")
      return redirect(url_for('restrictions'))
    
    flash(error)

  restrictions_list = g.conn.execute('SELECT * FROM dietary_restrictions')
  user_restrictions = g.conn.execute('SELECT diet_name FROM has_restriction WHERE email = %s', email)
  return render_template('restrictions.html', restrictions_list=restrictions_list, user_restrictions=user_restrictions)

@app.route('/restrictions/delete/<diet_name>', methods=['POST'])
@login_required
def deleterestriction(diet_name):
  g.conn.execute('DELETE FROM has_restriction WHERE email = %s AND diet_name = %s', g.user['email'], diet_name)
  return redirect(url_for('restrictions'))

@app.route('/shoppinglist', methods=['GET'])
@login_required
def shoppinglist():
  email = g.user['email']

  shopping_recipes = g.conn.execute('SELECT R.url, R.recipe_name \
    FROM recipes R NATURAL JOIN add_to_shopping_list S \
    WHERE S.email = %s', email)

  shopping_list = g.conn.execute('SELECT DISTINCT IR.food_name \
    FROM in_recipe IR NATURAL JOIN add_to_shopping_list S \
    WHERE S.email = %s \
    EXCEPT \
    SELECT DISTINCT SD.food_name FROM storage_details SD \
    WHERE SD.email = %s', email, email)

  return render_template('shoppinglist.html', shopping_recipes=shopping_recipes, shopping_list=shopping_list)


@app.route('/shoppinglist/add/<path:url>', methods=['POST'])
@login_required
def add_to_shoppinglist(url):
  email = g.user['email']
  error = None
  try:
    g.conn.execute('INSERT INTO add_to_shopping_list(email, url) VALUES (%s, %s)', email, url)
  except:
    error = 'Item already in your shopping list.'

  if not error == None:
    flash(error)

  return redirect(url_for('recipes'))

@app.route('/shoppinglist/delete/<path:url>', methods=['POST'])
@login_required
def delete_from_shoppinglist(url):
  g.conn.execute('DELETE FROM add_to_shopping_list WHERE email = %s AND url = %s', g.user['email'], url)
  return redirect(url_for('shoppinglist'))

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
