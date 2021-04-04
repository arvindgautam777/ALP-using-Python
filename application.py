#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Project: Part Reco
creation Date: Mon 07-10-2019
@author: Capgemini @bangalore
"""
from flask import Flask, request, jsonify, session,render_template,flash,session,g,redirect,url_for
from uuid import uuid4
import json
import requests

import sqlite3
from os import path
from hashlib import sha256
from datetime import datetime as DT
import pandas as pd


File = "SmartSearchData.xlsx"
df=pd.read_excel(File)
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/' 			# Creates a random key


def db_connect():
	if path.isfile("HPDatabase.db"):
		conn = sqlite3.connect("HPDatabase.db")
		return conn
	else:
		return None


@app.before_request
def before_request():
    g.user = None
    if 'user' in session :
        g.user = session['user']



@app.route('/login')
def login():
    if 'user' in session:
        return render_template("profile.html")
    return render_template("login.html")

@app.route('/jquerytest')
def jquerytest() :
    return render_template("jquerytest.html",Specific_Symptom=df['Specific_Symptom'],Symptom_Sub_Category=df['Symptom_Sub_Category'],Symptom_Top_Category=df['Symptom_Top_Category'],Business_Segment=df['Business_Segment'],Case_OTC=df['Case_OTC'],PO_Created_Site_Name=df['PO_Created_Site_Name'],Product_Number=df['Product_Number'],Case_Subject=df['Case_Subject'])

@app.route('/login', methods=['POST'])
def login_post():
    
    if request.method == 'POST':
        conn = db_connect()
        cur = conn.cursor()
        email = request.form.get("email")
        password = request.form.get("password").encode('utf-8', errors='ignore')
    
        encryptPassword = str(sha256(password).hexdigest())
    
        query = """SELECT user_id, username, password from HPUsers where email = '{uname}' and flag= 'Active'""".format(uname=email)
        data = cur.execute(query)
        res = cur.fetchall()
        conn.close()
        
        if any(res):
            data = [dat[0] for dat in data.description]
            response = dict(zip(data, res[0]))
            if response['password'] == encryptPassword:
             
                session['user'] = response["user_id"]
                return redirect(url_for("get_part_predictions"))
                #return jsonify({"status":"login successful", "response" :resp, "user_id":response["user_id"]})
    
            else:
                flash ("Login Failed Incorrect password")
                return redirect(url_for("login"))
                #return jsonify({"status":"login failed", "response":"incorrect password"})
    
        else:
            #resp = "%s doesnot exist" %email
            #return jsonify({"status":"Invalid user", "response":resp})
            flash ("Email does not exists")
            return redirect(url_for("login"))
            
    else:
        pass

@app.route('/logout')
def logout():
    session.pop('user',None)
    return redirect(url_for('index'))



@app.route('/get_part_predictions')
def get_part_predictions():
    if 'user' not in session  :
        return redirect(url_for("login"))
    return render_template("profile.html",Specific_Symptom=df['Specific_Symptom'],Symptom_Sub_Category=df['Symptom_Sub_Category'],Symptom_Top_Category=df['Symptom_Top_Category'],Business_Segment=df['Business_Segment'],Case_OTC=df['Case_OTC'],PO_Created_Site_Name=df['PO_Created_Site_Name'],Product_Number=df['Product_Number'],Case_Subject=df['Case_Subject'])

@app.route('/part_reco_engine',methods=['GET','POST'])
def part_reco_engine():
    if 'user' not in session  :
        return redirect(url_for("login"))
    try:
        if request.method == 'POST' :
            data = request.form.to_dict()
            print(data)
            #data = data.to_dict()
            values={}
            #data1=list(data.keys())
            #print(data1)
            Predicted_parts=''
            Predicted_comm=''
            headers = {'Content-type': 'application/json'}
            data1= json.dumps(data)
            #print(data1)
            url = "https://prod-26.centralus.logic.azure.com:443/workflows/eae68dfad0f44c3f90578376a0b11559/triggers/manual/paths/invoke?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=1Ae776A3JOwt_hiDCQj2uPE36zSb6D7mozJL0eHuUkM"
            rsp = requests.post(url, json=data, headers=headers)
           # print(data,rsp)
            response=rsp.content.decode('utf-8')
            #print(response)
            response_data=json.loads(response)
            if 'Status' in response_data:
                if response_data['Status']=="Check for valid Inputs":
                    #flash ("Please Validate the Inputs")
                    return jsonify({"error":"Please Validate the Inputs"})
                    return redirect(url_for("get_part_predictions"))
                if response_data['Status']=="Nothing Found":
                    #flash ("Nothing Found")
                    return jsonify({"error":"Nothing Found"})
                    return redirect(url_for("get_part_predictions"))
                if response_data['Status']=="Something went wrong":
                    #flash ("Fatal Error On API")
                    return jsonify({"error":"Fatal Error On API"})
                    return redirect(url_for("part_reco_engine"))
            
            else :
                Predicted_parts=response_data['Predicted_parts']
                Predicted_comm=response_data['Predicted_comm']
                #flash ("Predicted as ")
                return jsonify({"Predicted_comm":Predicted_comm,"Predicted_parts":Predicted_parts})
                return render_template("profile.html",Specific_Symptom=df['Specific_Symptom'],Symptom_Sub_Category=df['Symptom_Sub_Category'],Symptom_Top_Category=df['Symptom_Top_Category'],Business_Segment=df['Business_Segment'],Case_OTC=df['Case_OTC'],PO_Created_Site_Name=df['PO_Created_Site_Name'],Product_Number=df['Product_Number'],Case_Subject=df['Case_Subject'],Predicted_comm=Predicted_comm,Predicted_parts=Predicted_parts,form=data)
        else:
            return render_template("profile.html",Specific_Symptom=df['Specific_Symptom'],Symptom_Sub_Category=df['Symptom_Sub_Category'],Symptom_Top_Category=df['Symptom_Top_Category'],Business_Segment=df['Business_Segment'],Case_OTC=df['Case_OTC'],PO_Created_Site_Name=df['PO_Created_Site_Name'],Product_Number=df['Product_Number'],Case_Subject=df['Case_Subject'])
            
    except Exception as e:
        return e
        
@app.route("/")
def index() :
    return render_template("index.html")


if __name__ == '__main__':
	app.run(debug=True, port=5004)