from flask import Flask, request, render_template, session, flash, abort, redirect
from datetime import timedelta


app = Flask(__name__)
app.secret_key  = "secret"

@app.route("/")
def index():
    return render_template("main.html")

if __name__ == "__main__":
    app.run(debug=True, port=4000)
