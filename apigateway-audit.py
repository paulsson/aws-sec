#!/usr/bin/env python3

"""
This script audits all API Gateways in the given AWS region.
It reports how each gateway resource and http verb/method is secured.
The output can be formatted as either json or csv. CSV format is handy if you need to
share the audit reports with a point hair manager so they can open in a spreadsheet.
This script can be setup to be run on AWS lambda on a schedule if desired and then
deliver the reports to some location or send out an alert if an endpoint is not secured
properly.
See boto3 docs for details on functions and response bodies from AWS ApiGateway:
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/apigateway.html
NEVER pass in AWS credentials as parameters. NEVER EVER put credentials in your code!
Use the standard, best practice way to automatically discover credentials:
https://aws.amazon.com/blogs/security/a-new-and-standardized-way-to-manage-credentials-in-the-aws-sdks/
"""

import argparse
import boto3
import logging
import json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--region", help="The AWS region to check")
    parser.add_argument("-p", "--profile", help="Your AWS credentials profile to use")
    parser.add_argument("-m", "--methods", nargs='+', help="The http methods to check on the api resources (optional). If not set, all http methods will be checked.")
    parser.add_argument("-f", "--format", choices=['json', "json-pretty",'csv'], help="The output format, json or csv. Defaults to json.")
    parser.add_argument("-d", "--debug", action='store_true', help="Print out debug info to inspect API Gateway response data.")
    args = parser.parse_args()

    if not args.region:
        print("No region specified, attempting to use your default region if configured")
    if not args.profile:
        print("No AWS profile specified, attempting to use your default profile if configured")
    if not args.format:
        args.format = "json"

    auditor = ApiGatewayAuditor(args.profile, args.region, args.methods, args.format, args.debug)
    api_audits = auditor.audit()
    auditor.print_audits(api_audits)

class ApiGatewayAuditor:
    
    def __init__(self, profile=None, region=None, methods=None, format="json", debug=False):
        self.logger = logging.getLogger(__name__)
        console = logging.StreamHandler()
        self.logger.addHandler(console)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.ERROR)
        
        self.methods = methods
        self.format = format
        self.logger.debug(f"profile:{profile},region:{region},methods:{methods},format:{format}")
        
        session = boto3.Session(profile_name=profile, region_name=region)
        self.apigw = session.client('apigateway')
    
    def audit(self):
        response = self.apigw.get_rest_apis()
        api_audits = []
        items = response['items']
        self.logger.debug(f"Number of API Gateways: {len(items)}")
        self.logger.debug(f"Rest APIs: {response}")
        for item in items:
            api_id = item['id']
            name = item['name']
            endpoint_type = item['endpointConfiguration']['types']
            d = {'api_id':api_id, 'name':name, 'endpoint_type':endpoint_type}
            rescResp = self.apigw.get_resources(restApiId=api_id, embed=['methods'])
            if(rescResp['items']):
                resources = []
                for item in rescResp['items']:
                    res_dict = self.parse_resource(item)
                    (resources.append(res_dict) if res_dict is not None else None)
                if resources:
                    d['resources'] = resources
            api_audits.append(d)
        return api_audits

    def parse_resource(self, resource):
        self.logger.debug(f"resoure: {resource}")
        path = resource['path']
        methods = []
        result = None
        if 'resourceMethods' in resource:
            for key, value in resource['resourceMethods'].items():
                method = value['httpMethod']
                if self.methods is None or method in self.methods:
                    authorization_type = value['authorizationType']
                    api_key_required = value['apiKeyRequired']
                    d = {'method':method, 'authorization_type':authorization_type, 'api_key_required':api_key_required}
                    methods.append(d)
        if methods:
            result = {"path": path, "methods": methods}
        return result

    def print_audits(self, api_audits):
        if self.format == "json-pretty":
            print(json.dumps(api_audits, indent=4, sort_keys=True))
        elif self.format == "json":
            print(json.dumps(api_audits))
        else:
            for api in api_audits:
                for resource in api['resources']:
                    if resource['methods']:
                        for method in resource['methods']:
                            print(f"{api['name']},{api['api_id']},{api['endpoint_type']},{resource['path']},{method['method']},{method['authorization_type']},{method['api_key_required']}")

if __name__== "__main__":
    main()
