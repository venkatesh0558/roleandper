from flask import *
import mongo_rp
import json

app = Flask(__name__)


@app.route('/role/create', methods=['POST'])
def rolecreate():
    if request.method == 'POST':
        entity_data=request.json
        names = ('Role_Name', 'permissions_id',)
        re_dataset=set(names).issubset(entity_data)
        print(re_dataset)
        try:
            if re_dataset is True:
                    res= mongo_rp.entity_insert(data=entity_data)
                    print(res)
                    return res
            else:
                return "Something missing your data fields, fields must have ('Role_Name', 'permissions_id',)"
        except:
            return "something wrong please try again"

@app.route('/role/list', methods=['GET'])
def rolegetdata():
    if request.method == 'GET':
        res= mongo_rp.entity_get()
        print(res)
        res_json=json.loads(res)
        res_data={"respond":res_json}
        return res_data

@app.route('/role/update', methods=['PUT'])
def roleupdate():

    if request.method == 'PUT':
        entity_data = request.json
        names = ('Role_Name', 'updatedata')
        re_dataset = set(names).issubset(entity_data)
        print(re_dataset)
        try:
            if re_dataset is True:
                res = mongo_rp.entity_update(data=entity_data)
                print(res)
                return res
            else:
                return "Something missing your entity update fields"
        except:
            return "something wrong please try again"

@app.route('/role/active', methods=['GET'])
def active():
    if request.method == 'GET':
        res_data = {"respond": True}
        return res_data


@app.route('/role/deactive', methods=['GET'])
def deactive():
    if request.method == 'GET':
        res_data = {"respond": False}
        return res_data
@app.route('/role/assign', methods=['GET'])
def assign():
    if request.method == 'GET':
        res_data = {"respond": False}
        return res_data
@app.route('/role/unassign', methods=['GET'])
def assign():
    if request.method == 'GET':
        res_data = {"respond": False}
        return res_data
@app.route('/per/create', methods=['POST'])
def Pemissionsuser():
    if request.method == 'POST':
        entity_data = request.json
        if entity_data:
            names = ('per', 'per_list')
            re_dataset = set(names).issubset(entity_data)
            print(re_dataset)
            try:
                if re_dataset is True:
                    res = mongo_rp.user_insert(data=entity_data)
                    print(res)
                    return res
                else:
                    return "Something missing your user fields"
            except:
                return "something wrong please try again"
        else:
            return "Please give required data"
# @app.route('/per/list', methods=['GET'])
# def userget(current_user,clientdata, *args, **kwargs):
#     if request.method == 'GET':
#         print(clientdata)
#         print(current_user)
#         res=mongo_rp.user_get()
#         # print(json.dumps(res))
#         # res_json=json.loads(res)
#         res_data={"respond":res}
#         return jsonify(res_data)
# @app.route('/per/update', methods=['PUT'])
# def userupdatedata(urrent_user,clientdata, *args, **kwargs):
#
#     if request.method == 'PUT':
#         user_data = request.json
#         names = ('Email_Address', 'updatedata')
#         re_dataset = set(names).issubset(user_data)
#         print(re_dataset)
#         try:
#             if re_dataset is True:
#                 res = mongo_rp.user_update(data=user_data)
#                 print(res)
#                 return res
#             else:
#                 return "Something missing your user update fields"
#         except:
#             return "something wrong please try again"
# @app.route('/per/delete', methods=['DELETE'])
# def userdeletedata(urrent_user,clientdata, *args, **kwargs):
#     if request.method == 'DELETE':
#         entity_data=request.json
#         print(entity_data)
#         res=mongo_rp.user_delete(data=entity_data)
#         print(res)
#         return res
#

if __name__ == '__main__':

    app.run(debug=True,port=50099)