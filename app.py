from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from boto3 import resource
import pymysql
import os
import uuid
import secrets
import boto3

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = secrets.token_hex(16)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)
# AWS configurations
REGION_NAME = "us-west-1"  # Change this to your desired region
ec2 = boto3.resource('ec2', region_name=REGION_NAME)

def get_db_connection():
    return pymysql.connect(host="13.57.240.234", user="usertest", password="Makemein#007", database="ananya")


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

@app.route('/')
def home():
    return render_template('home.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")  # Added this line
        email = request.form.get("email")
        password = request.form.get("password")

        # Ensure a connection to the database
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check if user with the same username or email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s OR username = %s", (email, username))
        account = cursor.fetchone()

        # If an account with this email or username is found, return an error
        if account:
            msg = "Account already exists with this email or username!"
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
            connection.commit()
            msg = "You have successfully registered!"
        cursor.close()

    elif request.method == "GET":
        msg = ""
    return render_template("register.html", msg=msg)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[3], password):
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    # Your logout logic goes here. Typically, you will clear the session and then redirect the user to the login page.
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('There is no account with that email. You must register first.', 'warning')
            return redirect(url_for('register'))

    return render_template('forgot.html')

@app.route('/dashboard')
def dashboard():
   # Retrieve S3 buckets
    s3 = boto3.client('s3', region_name=REGION_NAME)
    buckets = [bucket['Name'] for bucket in s3.list_buckets()['Buckets']]

    # Retrieve EC2 instances
    ec2_resource = resource('ec2', region_name=REGION_NAME)
    instances = [instance.id for instance in ec2_resource.instances.all()]

    return render_template('dashboard.html', buckets=buckets, instances=instances)

@app.route('/buckets/<bucket_name>')
def bucket_contents(bucket_name):
    s3 = boto3.client(
        's3',
        aws_access_key_id='AKIAZ6UH7XMEQ55F3ON5',
        aws_secret_access_key='daTUt6mq8qb8GfzAA8EhKlJjs+CBkiNGCfvKVwke',
        region_name='us-west-2' # update this to your preferred region
    )
    
    response = s3.list_objects(
        Bucket=bucket_name
    )
    
    files = []
    if 'Contents' in response:
        files = [item['Key'] for item in response['Contents']]
    
    return render_template('bucket_contents.html', files=files, bucket_name=bucket_name)
@app.route('/ec2_instances')
def ec2_instances():
    
                         
    # Get filters from request args. If not provided, default to 'all'
    state_filter = request.args.get('state', 'all')
    type_filter = request.args.get('type', 'all')

    ec2 = boto3.resource('ec2')
    instances = ec2.instances.all()

    filters = []

    if state_filter != 'all':
        filters.append({
            'Name': 'instance-state-name',
            'Values': [state_filter]
        })

    if type_filter != 'all':
        filters.append({
            'Name': 'instance-type',
            'Values': [type_filter]
        })

    instances = ec2.instances.filter(Filters=filters)

    return render_template('ec2_instances.html', instances=instances)
                           
if __name__ == "__main__":
    #app.run(port=5005)
    app.run(debug=True)
