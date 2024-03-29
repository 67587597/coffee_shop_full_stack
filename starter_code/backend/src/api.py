import requests
import sys
import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
# db_drop_and_create_all()

# ROUTES
'''
@TODO implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks}
    where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks')
def get_drinks():
    try:
        drinks = Drink.query.all()
        drink_list = [drink.short() for drink in drinks]
        return jsonify({"success": True,
                        "drinks": drink_list
                        }), 200
    except requests.exceptions.HTTPError:
        abort(500)


'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks}
    where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def get_drink_detail():
    try:
        drinks = Drink.query.all()
        drink_list = [drink.long() for drink in drinks]
        return jsonify({"success": True,
                        "drinks": drink_list
                        }), 200
    except requests.exceptions.HTTPError:
        abort(500)


'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink}
    where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def add_drink():
    try:
        drink_list = []
        data = request.get_json()
        if 'title' not in data or 'recipe' not in data:
            abort(404)

        title = data['title']
        recipe = data['recipe']

        try:
            drink = Drink(title=title, recipe=json.dumps(recipe))
            drink.insert()
        except requests.exceptions.HTTPError:
            abort(422)

        print('inserted')
        drinks = Drink.query.filter(Drink.title == title).all()

        if len(drinks) != 0:
            drink_list = [drink.long() for drink in drinks]

        return jsonify({"success": True,
                        "drinks": drink_list
                        }), 200
    except requests.exceptions.HTTPError:
        abort(500)


'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink}
    where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def edit_drink(id):
    try:
        drink_list = []
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        if drink is None:
            abort(404)

        data = request.get_json()

        if 'title' in data:
            drink.title = data['title']
            drink.update()

        if 'recipe' in data:
            drink.recipe = data['recipe']
            drink.update()

        drinks = Drink.query.filter(Drink.title == data['title']).all()

        if len(drinks) != 0:
            drink_list = [drink.long() for drink in drinks]

        return jsonify({"success": True,
                        "drinks": drink_list
                        }), 200
    except requests.exceptions.HTTPError:
        abort(500)


'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id}
    where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''


@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(id):
    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()
        if drink is None:
            abort(404)
        drink.delete()

        return jsonify({"success": True,
                        "delete": id
                        }), 200
    except requests.exceptions.HTTPError:
        abort(500)


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
                    "success": False,
                    "error": 422,
                    "message": "unprocessable"
                    }), 422


'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''

'''
@TODO implement error handler for 404
    error handler should conform to general task above
'''


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": 404,
        "message": "resource not found"
    }), 404


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above
'''


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "success": False,
        "error": 401,
        "message": "unauthorized"
    }), 401


@app.errorhandler(403)
def permission_npt_found(error):
    return jsonify({
        "success": False,
        "error": 403,
        "message": "Permission not found"
    }), 401


@app.errorhandler(400)
def bad_request(error):
    return jsonify({"success": False,
                    "error": 400,
                    "message": "Bad request"}), 400


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"success": False,
                    "error": 500,
                    "message": "Internal server error"}), 500


@app.errorhandler(AuthError)
def auth_error(error):
    return jsonify({"success": False,
                    "error": error.status_code,
                    "message": error.error}), error.status_code
