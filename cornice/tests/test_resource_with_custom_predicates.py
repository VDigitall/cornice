# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import json

from pyramid import testing
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import Allow
from pyramid.httpexceptions import (
    HTTPOk, HTTPForbidden
)
from webtest import TestApp
import mock

from cornice.resource import resource
from cornice.resource import view
from cornice.schemas import CorniceSchema
from cornice.tests import validationapp
from cornice.tests.support import TestCase, CatchErrors
from cornice.tests.support import dummy_factory

import pdb

EMPLOYEES = {
    1: {'name': 'Tony Flash', 'position': 'topmanager', 'salary': 30000},
    2: {'name': 'Jimmy Arrow', 'position': 'supervisor', 'salary': 50000}
}

class employeeType(object):
    def __init__(self, val, config):
        self.val = val

    def text(self):
        return 'position = %s' % (self.val,)

    phash = text

    def __call__(self, context, request):
        if request.params.get('position') is not None:
            position = request.params.get('position')
            return position == self.val
        return False


@resource(collection_path='/company/employees', path='/company/employees/{id}',
          name='Topmanagers', position=u'topmanager')
class EManager(object):

    def __init__(self, request, context=None):
        self.request = request
        self.context = context

    @view()
    def collection_get(self):
        return {'employees': list(EMPLOYEES), 'cget': 'Topmanagers'}

    @view()
    @view()
    def get(self):
        employee = EMPLOYEES.get(int(self.request.matchdict['id']))
        employee['get'] = 'Topmanagers'
        return employee

    @view(renderer='json', accept='text/json')
    def collection_post(self):
        return {'post': 'Topmanagers'}

    def patch(self):
        return {'patch': 'Topmanagers'}

    def collection_patch(self):
        return {'cpatch': 'Topmanagers'}

    def put(self):
        return {'put': 'Topmanagers'}


@resource(collection_path='/company/employees', path='/company/employees/{id}',
          name='Supervisors', position=u'supervisor')
class ESupervisor(object):

    def __init__(self, request, context=None):
        self.request = request
        self.context = context

    @view()
    def collection_get(self):
        return {'employees': list(EMPLOYEES), 'cget': 'Supervisors'}

    @view()
    @view()
    def get(self):
        employee = EMPLOYEES.get(int(self.request.matchdict['id']))
        employee['get'] = 'Supervisors'
        return employee

    @view(renderer='json', accept='text/json')
    def collection_post(self):
        return {'post': 'Supervisors'}

    def patch(self):
        return {'patch': 'Supervisors'}

    def collection_patch(self):
        return {'cpatch': 'Supervisors'}

    def put(self):
        return {'put': 'Supervisors'}


class TestCustomPredicates(TestCase):

    def setUp(self):
        from pyramid.renderers import JSONP
        self.config = testing.setUp()
        self.config.add_renderer('jsonp', JSONP(param_name='callback'))
        self.config.include("cornice")
        self.authz_policy = ACLAuthorizationPolicy()
        self.config.set_authorization_policy(self.authz_policy)

        self.authn_policy = AuthTktAuthenticationPolicy('$3kr1t')
        self.config.set_authentication_policy(self.authn_policy)
        self.config.add_route_predicate('position', employeeType)
        self.config.scan("cornice.tests.test_resource_with_custom_predicates")
        self.app = TestApp(CatchErrors(self.config.make_wsgi_app()))

    def tearDown(self):
        testing.tearDown()

    def test_get_resource_with_predicates(self):
        # Tests for resource with name 'Supervisors'
        res = self.app.get('/company/employees', {'position': 'supervisor'}).json
        self.assertEqual(res['cget'], 'Supervisors')
        res = self.app.get('/company/employees/1', {'position': 'supervisor'}).json
        self.assertEqual(res['get'], 'Supervisors')
        res = self.app.post('/company/employees', {'name': 'Jimmy Arrow', 'position': 'supervisor', 'salary': 50000}).json
        self.assertEqual(res['post'], 'Supervisors')
        res = self.app.patch('/company/employees', {'id': 2, 'name': 'Jimmy Arrow', 'position': 'supervisor', 'salary': 55000}).json
        self.assertEqual(res['cpatch'], 'Supervisors')
        res = self.app.patch('/company/employees/2', {'name': 'Jimmy Arrow', 'position': 'supervisor', 'salary': 60000}).json
        self.assertEqual(res['patch'], 'Supervisors')
        res = self.app.put('/company/employees/2', {'position': 'supervisor', 'salary': 53000}).json
        self.assertEqual(res['put'], 'Supervisors')

        # Tests for resource with name 'Topmanagers'
        res = self.app.get('/company/employees', {'position': 'topmanager'}).json
        self.assertEqual(res['cget'], 'Topmanagers')
        res = self.app.get('/company/employees/1', {'position': 'topmanager'}).json
        self.assertEqual(res['get'], 'Topmanagers')
        res = self.app.post('/company/employees', {'name': 'Jimmy Arrow', 'position': 'topmanager', 'salary': 30000}).json
        self.assertEqual(res['post'], 'Topmanagers')
        res = self.app.patch('/company/employees', {'id': 2, 'name': 'Jimmy Arrow', 'position': 'topmanager', 'salary': 35000}).json
        self.assertEqual(res['cpatch'], 'Topmanagers')
        res = self.app.patch('/company/employees/2', {'name': 'Jimmy Arrow', 'position': 'topmanager', 'salary': 40000}).json
        self.assertEqual(res['patch'], 'Topmanagers')
        res = self.app.put('/company/employees/2', {'position': 'topmanager', 'salary': 33000}).json
        self.assertEqual(res['put'], 'Topmanagers')
