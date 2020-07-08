from flask import Flask
from flask_restful import Resource, Api
import casbin
import casbin_sqlalchemy_adapter
from flask import request
import json
from flask_cors import CORS
app = Flask(__name__)
api = Api(app)
adapter = casbin_sqlalchemy_adapter.Adapter('sqlite:///casbin_rbac.db')
check_role = {
    "karan": "admin",
    "rohit": "basic"
  }
CORS(app)
class LOGIN(Resource):

  def __init__(self):
    pass

  def post(self):  
    try:
      e = casbin.Enforcer("./casbin_model/rbac_model.conf", adapter, True)
      data = json.loads(request.data)
      username = data['username']
      if(username in check_role):
        role = check_role[username]
        data = e.get_permissions_for_user(role)
        # e.add_named_policy('p', ["ADMIN", "./athletes","DELETE"])
        user = {"username": username,"role":data[0][0]}
        return  ({ "success":True,"code":200,"error":"false", "data":data, "user":user })
      else:
        return ({"success":False,"code":200,"error":True,"message":"Please Enter Valid Username and Password"})

    except:
      return ({"success":False,"code":200,"error":True,"message":"Please Enter Username and Password"})




class USER(Resource):
    def get(self):
      e = casbin.Enforcer("./casbin_model/rbac_model.conf", adapter, True)

      data = json.loads(request.data)
      username= data["username"]
      if(username in check_role):
          role = check_role[username]
          if e.enforce(role, '/user', 'GET'):
            return ({"Authorization Status":"Success"})
          else:
            return ({"Authorization Status":"DENIAL"}) 
    
    
    def post(self):
      e = casbin.Enforcer("./casbin_model/rbac_model.conf", adapter, True)
      data = json.loads(request.data)
      username= data["username"]
      if(username in check_role):
          role = check_role[username]
          if e.enforce(role, '/user', 'POST'):
            return ({"Authorization Status":"Success"})
          else:
            return ({"Authorization Status":"DENIAL"}) 

    def put(self):
      e = casbin.Enforcer("./casbin_model/rbac_model.conf", adapter, True)
      data = json.loads(request.data)
      username= data["username"]
      if(username in check_role):
          role = check_role[username]
          if e.enforce(role, '/user', 'PUT'):
            return ({"Authorization Status":"Success"})
          else:
            return ({"Authorization Status":"DENIAL"}) 

    def delete(self):
      e = casbin.Enforcer("./casbin_model/rbac_model.conf", adapter, True)
      data = json.loads(request.data)
      username= data["username"]
      if(username in check_role):
          role = check_role[username]
          if e.enforce(role, '/user', 'DELETE'):
            return ({"Authorization Status":"Success"})
          else:
            return ({"Authorization Status":"DENIAL"}) 

api.add_resource(LOGIN,'/login')
api.add_resource(USER,'/user')


if(__name__ == "__main__"):
  app.run(debug = True)

  
 
