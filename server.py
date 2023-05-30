from flask import Flask, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
import json

app = Flask(__name__)
db = SQLAlchemy()

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mishark.db"
db.init_app(app)

path = "pcap.json"

def ReadJson(path):
    with open(path, encoding='utf-8-sig') as json_data:
        data = json.load(json_data)
    return data


@app.route('/')
def main_page():
    data = ReadJson(path)
    return render_template('index.html',pcap_data = data)


if __name__ == '__main__':
    app.run(debug=True)