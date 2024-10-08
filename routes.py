from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import *

def registrate_routes(app, db):
    @app.route('/')
    def index():
        return f"Hello, {Users.query.get('admin').name}!"
    @app.route('/registrate', methods=['GET', 'POST'])
    def registrate():
        if request.method == 'POST':
            return "none"
        return "registrate"