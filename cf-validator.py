#!/usr/bin/env python

from __future__ import print_function
import boto3
import botocore
import time
import sys
import argparse
import json
from pprint import pprint

def get_configuration(rules_file):

    '''
        Read a configuration from file or local
    '''
    f = open(rules_file, "r")
    cf_rules = f.read()
    j_rules = json.loads(cf_rules)

    valid_root_keys = j_rules["valid_root_keys"]
    valid_parameters = j_rules["valid_parameters"]
    valid_resources = j_rules["valid_resources"]
    require_ref_attributes = j_rules["require_ref_attributes"]
    allow_additional_attributes = j_rules["allow_additional_attributes"]
    banned_attributes = j_rules["banned_attributes"]

    #valid_root_keys = ['AWSTemplateFormatVersion','Parameters','Resources','Outputs']
    #valid_parameters = ['p1','p2']
    #valid_resources = ['EC2::Instance']
    #require_ref_attributes = {'EC2::Instance' : ['InstanceType','ImageId','SecurityGroupIds','SubnetId']}
    #require_ref_attributes = {}
    #allow_additional_attributes = {'EC2::Instance' : ['KeyName','IamInstanceProfile','Tags']}
    #allow_additional_attributes = {}
    #banned_attributes = {'EC2::Instance' :['KeyName']}
    #banned_attributes = {}
    return valid_root_keys, valid_parameters, valid_resources, require_ref_attributes, allow_additional_attributes, banned_attributes

def get_template(template_file):

    '''
        Read a template file and return the contents
    '''

    f = open(template_file, "r")
    cf_template = f.read()
    return cf_template

def validate_cf_template(cf_template):

    '''
        Validate CF template
    '''

    try:
        client = boto3.client('cloudformation', region_name='us-east-1')
        response = client.validate_template(TemplateBody=cf_template)
        if 'Capabilities' in response:
            print(response['Capabilities'],"=>>", response['CapabilitiesReason'])
            return False
        else:
            return True
    except:
        print(sys.exc_info()[1])
        return False

def validate_root_keys(cf_json_keys, valid_root_keys):

    '''
        Validate the root keys of CF template
    '''

    is_valid = False
    if not valid_root_keys:
        is_valid = True
    else:
        r = set(cf_json_keys) - set(valid_root_keys)
        if not r:
            is_valid = True

    return is_valid

def validate_parameters(cf_parameters, valid_parameters):

    '''
        Validate parameters of in CF template
    '''

    is_valid = False
    if not valid_parameters:
        is_valid = True
    else:
        r = set(cf_parameters) - set(valid_parameters)
        if not r:
            is_valid = True

    return is_valid

def validate_resources(cf_resources, valid_resources):

    '''
        Validate resources in CF template
    '''

    l_resource = []
    is_valid = False

    for rs in cf_resources.values():
        l_resource.append(rs["Type"].replace('AWS::',''))

    if (not valid_resources) or (not l_resource):
        is_valid = True
    else:
        r = set(l_resource) - set(valid_resources)
        if not r:
            is_valid = True

    return is_valid

def validate_attributes(cf_resources, require_ref_attributes, allow_additional_attributes, banned_attributes):

    '''
        Validate attributes of resources in CF template
    '''

    for rs in cf_resources.values():
        rs_type = rs["Type"].replace('AWS::','')
        ref_attr = []
        add_attr = []
        ban_attr = []
        if rs_type in require_ref_attributes:
            ref_attr = require_ref_attributes[rs_type]
        if rs_type in allow_additional_attributes:
            add_attr = allow_additional_attributes[rs_type]
        if rs_type in banned_attributes:
            ban_attr = banned_attributes[rs_type]

        if (ref_attr) or (add_attr) or (ban_attr):
            for atr_key in rs["Properties"].keys():
                if atr_key in ban_attr:
                    print('Banned Attribue')
                    return False
                elif atr_key in ref_attr:
                    atr_val = rs["Properties"][atr_key]
                    if isinstance(atr_val, dict) and atr_val.keys()[0] not in 'Ref':
                        print('Not Refference')
                        return False
                    elif isinstance(atr_val, list):
                        for o in atr_val:
                            if not isinstance(o, dict):
                                print('Not Refference - too nested')
                                return False
                            elif o.keys()[0] not in 'Ref':
                                print('Not Refference - sub value')
                                return False
                elif add_attr and atr_key not in add_attr:
                    print('Not in allow attributes')
                    return False

    return True

def validate_resources_exist(res_file):

    '''
        Validate if given AWS resource exists and are available
    '''

    is_Valid = True
    f = open(res_file, "r")
    cf_res = f.read()
    j_res = json.loads(cf_res)

    for r in j_res:
        if r["Type"] == "SG":
            try:
                ec2 = boto3.resource('ec2')
                sg = ec2.SecurityGroup(r["ID"]).group_name
            except:
                print(sys.exc_info()[1])
                is_Valid = False

        elif r["Type"] == "AMI":
            try:
                ec2 = boto3.resource('ec2')
                state = ec2.Image(r["ID"]).state
                if state != "available":
                    print("AMI Image not available")
                    is_Valid = False
            except:
                print(sys.exc_info()[1])
                is_Valid = False

        elif r["Type"] == "Subnet":
            try:
                ec2 = boto3.resource('ec2')
                state = ec2.Subnet(r["ID"]).state
                if state != "available":
                    print("Subnet not available")
                    is_Valid = False
            except:
                print(sys.exc_info()[1])
                is_Valid = False

    return is_Valid

def main(arguments):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--cf_path', required=True)
    parser.add_argument('--cf_rules', required=True)
    parser.add_argument('--cf_res',default='')
    args = parser.parse_args(arguments)

    cf_template = get_template(args.cf_path)
    j_cf = json.loads(cf_template)

    if not validate_cf_template(cf_template):
        sys.exit("CF Template not valid")

    valid_root_keys, valid_parameters, valid_resources, require_ref_attributes, allow_additional_attributes, banned_attributes = get_configuration(args.cf_rules)

    if not validate_root_keys(j_cf.keys(),valid_root_keys):
        sys.exit("Root Keys are not valid")

    if not validate_parameters(j_cf["Parameters"].keys(),valid_parameters):
        sys.exit("Parameters are not valid")

    if not validate_resources(j_cf["Resources"],valid_resources):
        sys.exit("Resources are not valid")

    if not validate_attributes(j_cf["Resources"],require_ref_attributes, allow_additional_attributes, banned_attributes):
        sys.exit("Require Resources are not valid")

    if args.cf_res:
        if not validate_resources_exist(args.cf_res):
            sys.exit("Resources not found")

    print("CloudFormation Template Valid")

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
