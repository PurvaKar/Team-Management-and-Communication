from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date
from sqlalchemy import update
import os

import time
from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from flask_socketio import SocketIO, send, emit, join_room, leave_room

from wtform_fields import *
from models import *



app = Flask(__name__)
appp = Flask(__name__)
file_path = os.path.abspath(os.getcwd())+"/database.db"
app.config['SECRET_KEY'] = 'oursecret'
appp.config['SECRET_KEY'] = 'oursecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path
appp.config['SQLALCHEMY_DATABASE_URI']= 'postgres://vhamzkemypxqmb:9f41c67dbf743a8d89cc8eee833552c1fcf16eb42dafe4c96a9d7b3a915bef52@ec2-52-0-155-79.compute-1.amazonaws.com:5432/d5h8odi3bmgm5g'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
appp.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
dbb = SQLAlchemy(appp)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Project(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    projectname = db.Column(db.String(15), unique=True)
    creator = db.Column(db.String(15), nullable=False)
    userid = db.Column(db.Integer, nullable=False)
    projects = db.relationship('Projectdetail', backref='author', lazy=True)

class PersonalTask(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, nullable=False)
    task = db.Column(db.String(1500), nullable=False)

class Projectdetail(UserMixin, db.Model):
    userid = db.Column(db.Integer, primary_key=True)
    employeename = db.Column(db.String(15), nullable=False)
    designation = db.Column(db.String(15), nullable=False)
    projectid= db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

class ProjectTask(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(15), nullable=False)
    description = db.Column(db.String(15), nullable=False)
    status = db.Column(db.Text, nullable=False, default='UNSOLVED')
    addedby = db.Column(db.String(15), nullable=False)
    projectid= db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class AddForm(FlaskForm):
    projectname = StringField('Project Name', validators=[InputRequired(), Length( max=40)])
    role = StringField('Your Role', validators=[InputRequired()])

class AddTaskForm(FlaskForm):
    task = StringField('Task To-Do', validators=[InputRequired(), Length( max=1500)])

class AddEmpForm(FlaskForm):
    emp_name = SelectField('Employee Name', choices=[])
    role = StringField('Role', validators=[InputRequired()])

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired()])
    des = StringField('Description', validators=[InputRequired()])

socketio = SocketIO(app)
ROOMS = ["issues", "updates", "discussions", "general"]


@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        flash('Invalid username or password!')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account Created!')
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/myprojects', methods=['GET', 'POST'])
@login_required
def myproject():
    tasks = Projectdetail.query.filter_by(employeename=current_user.username).all()
    
    return render_template('myproject.html', tasks=tasks, name=current_user.username)

@app.route("/<int:project_id>/<string:project_name>/teamdetails", methods=['GET', 'POST'])
@login_required
def update_project(project_id, project_name):
    task = Project.query.get_or_404(project_id)
    
    form = AddEmpForm()
    form.emp_name.choices = [(user.username) for user in User.query.all()]
    if form.emp_name.data!=None and form.role.data!=None:
        doesexist = Projectdetail.query.filter_by(projectid=project_id, employeename=form.emp_name.data).all()
        if doesexist:
            flash('Employee Already Added!')
        else:
            new_user = Projectdetail(projectid=project_id, employeename=form.emp_name.data, designation=form.role.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Employee Added!')
    project = Projectdetail.query.filter_by(projectid=project_id).all()       
    return render_template('teamdetails.html', title='Update Project', task=task, legend='Update Project', name=current_user.username, form=form, project=project)

@app.route("/<int:project_id>/<string:project_name>/workdetails", methods=['GET', 'POST'])
@login_required
def workdetails(project_id, project_name):
    task = Project.query.get_or_404(project_id)
    form = AddEmpForm()
    form2 = TaskForm()
    form.emp_name.choices = [(user.username) for user in User.query.all()]
    if form.emp_name.data!=None and form.role.data!=None:
        doesexist = Projectdetail.query.filter_by(projectid=project_id, employeename=form.emp_name.data).all()
        if doesexist:
            flash('Employee Already Added!')
        else:
            new_user = Projectdetail(projectid=project_id, employeename=form.emp_name.data, designation=form.role.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Employee Added!')
    if form2.title.data !=None and form2.des.data!=None:
        new_issue = ProjectTask(title=form2.title.data, description=form2.des.data, addedby=current_user.username, projectid=project_id)
        db.session.add(new_issue)
        db.session.commit()
        flash('Issue Added!')

    project = ProjectTask.query.filter_by(projectid=project_id).all()       
    return render_template('workdetails.html', title='Update Project', task=task, form2=form2, legend='Update Project', name=current_user.username, form=form, project=project)


@app.route('/personaltask', methods=['GET', 'POST'])
@login_required
def personaltask():
    form = AddTaskForm()
    if form.task.data!=None:
        new_task = PersonalTask(userid=current_user.id, task=form.task.data)
        db.session.add(new_task)
        db.session.commit()
        flash('TASK ADDED!')
        return redirect(url_for('personaltask'))

    tasks = PersonalTask.query.filter_by(userid=current_user.id)
    return render_template('personaltask.html', tasks=tasks, form=form, name=current_user.username)


@app.route('/personaltask/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    taskd = PersonalTask.query.get_or_404(task_id)
    db.session.delete(taskd)
    db.session.commit()
    return redirect(url_for('personaltask'))


@app.route('/addproject', methods=['GET', 'POST'])
@login_required
def addproject():
    form = AddForm()

    if form.projectname.data != None:
        pro = Project.query.filter_by(projectname=form.projectname.data).first()
        if pro!=None: 
            flash('PROJECT NAME ALREADY EXIST!')
            return redirect(url_for('addproject'))
        else:
            new_project = Project(projectname=form.projectname.data, creator=current_user.username, userid=current_user.id)
            db.session.add(new_project)
            db.session.commit()
            pro = Project.query.filter_by(projectname=form.projectname.data).first()
            new_user = Projectdetail(projectid=pro.id, employeename=current_user.username, designation=form.role.data)
            db.session.add(new_user)
            db.session.commit()
            flash('PROJECT ADDED!')
            return redirect(url_for('dashboard'))


    return render_template('addproject.html', title='New Project', form=form, legend='New Project', name=current_user.username)



@app.route("/<int:project_id>/<string:project_name>/chat", methods=['GET', 'POST'])
@login_required
def chat(project_id, project_name):
    task = Project.query.get_or_404(project_id)
    return render_template("chat.html", username=current_user.username, rooms=ROOMS, task=task)


@app.errorhandler(404)
@login_required
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


@socketio.on('incoming-msg')
@login_required
def on_message(data):
    """Broadcast messages"""

    msg = data["msg"]
    username = data["username"]
    room = data["room"]
    # Set timestamp
    time_stamp = time.strftime('%b-%d %I:%M%p', time.localtime())
    send({"username": username, "msg": msg, "time_stamp": time_stamp}, room=room)


@socketio.on('join')
@login_required
def on_join(data):
    """User joins a room"""

    username = data["username"]
    room = data["room"]
    join_room(room)

    # Broadcast that new user has joined
    send({"msg": username + " has joined the " + room + " room."}, room=room)


@socketio.on('leave')
@login_required
def on_leave(data):
    """User leaves a room"""

    username = data['username']
    room = data['room']
    leave_room(room)
    send({"msg": username + " has left the room"}, room=room)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
