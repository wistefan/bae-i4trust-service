# -*- coding: utf-8 -*-

# Copyright (c) 2021 Future Internet Consulting and Development Solutions S.L.

# This file is part of BAE NGSI Dataset plugin.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import os
import re
import jwt
import json
import requests
from requests.exceptions import HTTPError
import uuid

import time

from django.conf import settings

from wstore.asset_manager.resource_plugins.plugin import Plugin
from wstore.asset_manager.resource_plugins.plugin_error import PluginError


CLIENT_ID = os.getenv('BAE_EORI', 'EU.EORI.NLMARKETPLA')
KEY = os.getenv('BAE_TOKEN_KEY', './certs/mplace.key')
CERT = os.getenv('BAE_TOKEN_CRT', './certs/mplace.crt')

UNITS = [{
    'name': 'Api call',
    'description': 'The final price is calculated based on the number of calls made to the API'
}]

class I4TrustService(Plugin):
    def build_token(self, params):
        def getCAChain(cert):

            sp = cert.split('-----BEGIN CERTIFICATE-----\n')
            sp = sp[1:]

            ca_chain = []
            for ca in sp:
                ca_sp = ca.split('\n-----END CERTIFICATE-----')
                ca_chain.append(ca_sp[0])

            return ca_chain

        iat = int(str(time.time()).split('.')[0])
        exp = iat + 30

        token = {
            "jti": str(uuid.uuid4()),
            "iss": params['client_id'],
            "sub": params['client_id'],
            "aud": [
                params['ar_id'],
                params['token_endpoint']
            ],
            "iat": iat,
            "nbf": iat,
            "exp": exp
        }

        with open(params['key'], 'r') as key:
            private_key = key.read()

        with open(params['cert'], 'r') as cert:
            ca_chain = getCAChain(cert.read())

        return jwt.encode(token, private_key, algorithm="RS256", headers={
            'x5c': ca_chain
        })

    def on_post_product_spec_validation(self, provider, asset):
        # Save IDP id with the offering meta data
        asset.meta_info['idp_id'] = provider.idp

        # Check vc type 
        if 'vc_type' not in asset.meta_info:
            raise PluginError('Verifiable Credential type must be specified.')

        # Check role name 
        if 'role_names' not in asset.meta_info:
            raise PluginError('Name of the roles must be specified.')

        # Set expiration duration
        try:
            asset.meta_info['minutes'] = int(asset.meta_info['minutes'])
        except:
            asset.meta_info['minutes'] = 10080  # One week

        asset.save()


    def _append_string_charact(self, charact, name, description, value):
        charact.append({
                "name": name,
                "description": description,
                "valueType": "string",
                "configurable": False,
                "productSpecCharacteristicValue": [{
                    "valueType": "string",
                    "default": True,
                    "value": value,
                    "unitOfMeasure": "",
                    "valueFrom": "",
                    "valueTo": ""
                }]
            })
        
    def on_post_product_spec_attachment(self, asset, asset_t, product_spec):
        # Load meta data as characteristics
        prod_url = '{}/api/catalogManagement/v2/productSpecification/{}'.format(
            settings.CATALOG, asset.product_id)


        # Get the product
        try:
            charact = product_spec['productSpecCharacteristic']

            # Add vc type
            if asset.meta_info['vc_type']: 
                self._append_string_charact(charact, 
                "Verifiable Credential type",
                "Type of verifiable credentials that can be issued.",
                asset.meta_info['vc_type'])

            # Add role name
            if asset.meta_info['role_names']: 
                self._append_string_charact(charact, 
                "Role name",
                "(Comma seperated) List of assingable roles.",
                asset.meta_info['role_names'])
             
            resp = requests.patch(prod_url, json={
                'productSpecCharacteristic': charact
            }, verify=False)

            resp.raise_for_status()
        except:
            # This is a nice to have, but the product is already created
            pass

    def on_post_product_offering_validation(self, asset, product_offering):
        pass

    def _get_access_token(self, asset):
        
        token_endpoint = asset.meta_info['ar_token_endpoint']

        # Generate local JWT
        token = self.build_token({
            'client_id': CLIENT_ID,
            'idp_id': asset.meta_info['idp_id'],
            'ar_id': asset.meta_info['ar_id'],
            'key': KEY,
            'cert': CERT,
            'token_endpoint': token_endpoint
        })

        auth_params = {
            'grant_type': 'client_credentials',
            'scope': 'iSHARE',
            'client_id': CLIENT_ID,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': token
        }

        response = requests.post(token_endpoint, data=auth_params)

        try:
            response.raise_for_status()
        except HTTPError as e:
            print(e.request.body)
            print(e)
            print(e.response.text)
            print(response.json())

            raise PluginError('Error validating JWT')

        auth_data = response.json()
        if 'access_token' not in auth_data:
            raise PluginError('No access token in response')

        return auth_data['access_token']

    def _create_policy(self, action, resource_type, ids_str, attrs_str):
        ids = ids_str.split(',')
        attributes = attrs_str.split(',')
        policy = {
            "target": {
                "resource": {
                    "type": resource_type,
                    "identifiers": ids,
                    "attributes": attributes
                },
                "actions": [action]
            },
            "rules": [{
                "effect": "Permit"
            }]
        }
        return policy

    def _create_vc(self, asset, order, not_before, not_after):

        # Set policies
        policies = []
        policies.append(self._create_policy("ISSUE", asset.meta_info['vc_type'], "*", asset.meta_info['role_names']))
         # Create delegation evidence to be updated
        delegation_evidence = {
            "delegationEvidence": {
                "notBefore": not_before,
                "notOnOrAfter": not_after,
                "policyIssuer": asset.meta_info['idp_id'],
                "target": {
                    "accessSubject": (order.owner_organization.issuerDid)
                },
                "policySets": [{
                    "target": {
			"environment": {
			    "licenses": [
				"ISHARE.0001"
			    ]
			}
		    },
                    "policies": policies
                }]
            }
        }
        return delegation_evidence

    def _create_role(self, asset, not_before, not_after):

        # Set policies
        policies = []

      
        # Notifications
        if asset.meta_info['notification_allowed']:
            policies.append(self._create_policy("POST:Notification", asset.meta_info['notification_resource_type'], asset.meta_info['notification_ids'], asset.meta_info['notification_attributes']))

        # Sidecar-Proxy endpoint config service
        if asset.meta_info['sidecar_endpoint_config_allowed']:
            policies.append(self._create_policy("POST", "EndpointConfig", "*", "*"))
            
        # Create delegation evidence to be updated
        delegation_evidence = {
            "delegationEvidence": {
                "notBefore": not_before,
                "notOnOrAfter": not_after,
                "policyIssuer": asset.meta_info['idp_id'],
                "target": {
                    "accessSubject": asset.meta_info['role_name'],
                },
                "policySets": [{
                    "target": {
			"environment": {
			    "licenses": [
				"ISHARE.0001"
			    ]
			}
		    },
                    "policies": policies
                }]
            }
        }

        return delegation_evidence

    def on_product_suspension(self, asset, contract, order):

        policy_endpoint = asset.meta_info['ar_policy_endpoint']

        # Policy expires now
        not_before = int(str(time.time()).split('.')[0])
        not_after = not_before

        # Create delegation evidence to be updated
        vc_evidence = self._create_vc(asset, order, not_before, not_after)

        # Get access token
        access_token = self._get_access_token(asset)

     
        policy_response_vc = requests.post(policy_endpoint, json=vc_evidence, headers={
             'Authorization': 'Bearer ' + access_token
        })


        try:
            policy_response_vc.raise_for_status()
        except HTTPError as e:
            print('HTTP  ERROR')
            print(e.request.body)
            print(e)
            print(e.response.text)

            raise PluginError('Error creating policy')
    
    def on_product_acquisition(self, asset, contract, order):

        policy_endpoint = asset.meta_info['ar_policy_endpoint']

        not_before = int(str(time.time()).split('.')[0])
        not_after = not_before + (asset.meta_info['minutes'] * 60)

        # Create new policy
        vc_evidence = self._create_vc(asset, order, not_before, not_after)
        
        # Get access token
        access_token = self._get_access_token(asset)

      
        policy_response_vc = requests.post(policy_endpoint, json=vc_evidence, headers={
             'Authorization': 'Bearer ' + access_token
        })

        try:
            policy_response_vc.raise_for_status()
        except HTTPError as e:
            print('HTTP  ERROR')
            print(e.request.body)
            print(e)
            print(e.response.text)

            raise PluginError('Error creating policy')

    def get_usage_specs(self):
        return UNITS

    def get_pending_accounting(self, asset, contract, order):
        return [], None


if __name__ == "__main__":
    plugin = I4TrustService()
    plugin.on_product_acquisition(None, None, None)
