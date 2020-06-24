import boto3
import json
from report_generator import Generator

# TODO  - add CLI args
#       - implement two diff audit styles: customer acc and service. customer acc has a few extra tests like password policies, mfa, etc.
#       - fix jinja template/bootstrap stuff
#       - fix some redundancy with client creation from when i started to inherit from auditr
#       - ELBV2 -> Access Logging, request smuggling protection, deletion protection
#       - Route53 -> Domain autorenew, domain transfer not locked,
class Auditor:
    def __init__(self, session, name):
        self.name = name
        self.session = session

    def get_client(self):
        return self.session.client(self.name)

    def audit(self):
        raise NotImplementedError

    def to_json(self):
        raise NotImplementedError

    def results_to_html(self, results):
        raise NotImplementedError



class ec2Auditor(Auditor):

    def __init__(self, session): #  Removed the client.parameter. We will inherit the client.from the Auditer class which inherits it from the driver
        super().__init__(session, "ec2")
        client = self.get_client()    #  Need to fix redundancy with these clients
        self.volumes = client.describe_volumes()["Volumes"]
        self.reservations = client.describe_instances()["Reservations"]
        self.securityGroups = client.describe_security_groups()["SecurityGroups"]
        self.testCases = {"VPC NACL": self.aclCheck, "IMDS": self.imdsCheck, "SSE": self.volumeEncryptionCheck}
        self.results = {'Findings': {'FlawedNACL': [], 'SSE_DISABLED': [], 'IMDSv1': []}}  # Store EC2 specific results


#  IMDSv2 implements SSRF prevention VIA preflighted requests that return a key that is used to sign subsequent requests to the internal metadata service
#  This prevents most SSRF vulns from querying the internal metadata service VIA ssrf as the request method can't be dynamically changed
#  By default, all VPCs have both IMDSv1 and IMDSv2 configured; however, the SSRF preflighted implementation is only enabled in IMDSv2. Though IMDSv2 is enabled by default, signed preflight tokens aren't enforced by default

    def imdsCheck(self):
        for instances in self.reservations:
            for instance in instances["Instances"]:
                if instance["MetadataOptions"]["HttpEndpoint"] == "enabled" and instance["MetadataOptions"]["HttpTokens"] == "optional":
                    finding = instance["InstanceId"]  # Saving a list of instance IDS into our results dict
                    self.results['Findings']['IMDSv1'].append(finding)  # self.results.append(finding)

# Network access control enumeration
# Default ec2 instances are shipped with over-permissive NACLs that allow unrestricted external access
# As a defense in depth measure, this should be scoped down via the CIDR notation

    def aclCheck(self):
        public_ports = [80,443,8080]
        bad_cidr = "0.0.0.0"
        for groups in self.securityGroups:
            for IpPermissions in groups["IpPermissions"]:
                 for IpRanges in IpPermissions["IpRanges"]:
                     if bad_cidr in IpRanges["CidrIp"] and IpPermissions["FromPort"] not in public_ports :
                         finding = groups["VpcId"] + " Port " + str(IpPermissions["FromPort"]) + " "  + IpRanges["CidrIp"]
                         self.results['Findings']['FlawedNACL'].append(finding)

# Server Side Encryption for EBS volumes.

    def volumeEncryptionCheck(self):
        for volumes in self.volumes:
            for attachments in volumes["Attachments"]:
                if not volumes["Encrypted"]:
                    finding = attachments["VolumeId"]
                    self.results['Findings']['SSE_DISABLED'].append(finding)

    def audit(self):
        client = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results


    def results_to_html(self, results):
        html = ["<br><br><center><h1>EC2 Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">Instances</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]

        for findings in results["Findings"]:
            #html.append("<tr><th scope=\"row\">%s</th></th>" % findings)
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html

    def generate_markdown(self):
        pass

        #for naclFinding in self.results["Findings"]["FlawedNACL"]:



class cloudFrontAuditor(Auditor):

    def __init__(self, session):
        super().__init__(session, "cloudfront")
        self.cloudFrontClient = self.get_client()
        self.testCases = {'logging': self.get_logging_status, 'http_status': self.get_http_status}
        self.results = {'Findings': {'LoggingDisabled': [], 'HTTPS_ENFORCEMENT': []} }


    def get_logging_status(self):
            for items in self.cloudFrontClient.list_distributions()["DistributionList"]["Items"]:
                if not self.cloudFrontClient.get_distribution_config(Id=items['Id'])["DistributionConfig"]["Logging"]:
                        finding = items['Id']
                        self.results['Findings']['Logging'].append(finding)

    def get_http_status(self):
        #CloudFront distributions should not allow HTTP
        for items in self.cloudFrontClient.list_distributions()["DistributionList"]["Items"]:
            try:
                if self.cloudFrontClient.get_distribution_config(Id=items['Id'])["DefaultCacheBehavior"]["ViewerProtocolPolicy"] != "https-only":
                    finding = {items['Id']: 'HTTPS not enforced on CloudFront CDN'}
                    self.findings['Findings']['HTTPS_ENFORCEMENT'].append(finding)
            except Exception as e:
                pass

    def audit(self):
        client = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()
#        if self.results["Findings"].keys() < 2
        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results

    def results_to_html(self, results):
        html = ["<br><br><center><h1>CloudFront Findings</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">CloudFront Distribution</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            #html.append("<tr><th scope=\"row\">%s</th></th>" % findings)
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html




class dynamodbAuditor(Auditor):

    def __init__(self, session):
       super().__init__(session, "dynamodb")
       self.ddbClient = self.get_client()
       self.results = {'Findings': {'PITR_DISABLED': []}}
       self.testCases = {'Point-in-Time Recovery': self.PITR_check}
       self.tables = self.ddbClient.list_tables()["TableNames"]


    def PITR_check(self):
        # Checks if the feature Point-in-Time Recovery (PITR) is enabled. Often this isn't enabled because of additional costs.
        # PITR provides continous backups for DynamoDB table data.
        # A case where this may be useful: NoSQL Injection allows mass deletion of data. PITR will create backups for all deleted data.
        for table in self.tables:
            if ddbClient.describe_continuous_backups(TableName = table)["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "DISABLED":
                print(table + " PITR disabled")

    def sse_check(self):
        #for table in self.tables:
        pass

    def results_to_html(self, results):
        html = ["<br><br><center><h1>DynamoDB Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">DynamoDB Table</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html





class snsAuditor(Auditor):

    def __init__(self, session):
        super().__init__(session, "sns")
        self.snsClient = self.get_client()

        self.topics = self.snsClient.list_topics()["Topics"]
        self.subscribers = self.snsClient.list_subscriptions()["Subscriptions"]
        self.testCases = {"Topic SSE": self.topicEncryptionCheck, "wildcarded permissions": self.topicIAMCheck}
        self.results = {'Findings': {'SSE_DISABLED': [], 'IAM_LOOSE_PERMISSIONS': []}}

    def topicEncryptionCheck(self):
        #SNS topics should be encrypted at rest.
        for topics in self.topics:
            attributes = self.snsClient.get_topic_attributes(TopicArn=topics["TopicArn"])
            try:
                attributes["Attributes"]["KmsMasterKeyId"]  # Exception will be thrown if SEE is disabled
            except Exception as e:
                finding = topics["TopicArn"]
                self.results['Findings']['SSE_DISABLED'].append(finding)

    def topicIAMCheck(self):
        #Over-permissive IAM policies occur often when service principals are wildcarded without conditionals.
        for topics in self.topics:  # Redundancy here
            attributes = self.snsClient.get_topic_attributes(TopicArn=topics["TopicArn"])
            policy = json.loads(attributes["Attributes"]["Policy"])
            for statements in  policy["Statement"]:
                if statements["Principal"]["AWS"] == '*' and 'Condition' not in statements:
                    finding = {topics["TopicArn"]: {"Wildcarded permissions allow all to perform certain operations": statements.get("Action")}}
                    self.results['Findings']['IAM_LOOSE_PERMISSIONS'].append(finding)

    def audit(self):
        client = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results

    def results_to_html(self, results):
        html = ["<br><br><center><h1>SNS Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">Topics</th>",
                "<th scope=\"col\">Description</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            #html.append("<tr><th scope=\"row\">%s</th></th>" % findings)
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html



class s3Auditor(Auditor):

    def __init__(self, session):
        super().__init__(session, "s3")
        self.s3client = self.get_client()
        self.results = {'Findings':{'SSE_DISABLED': [], 'AccessLoggingDisabled': [], 'VersioningDisabled': [], 'Publicbucket': []}}
        self.testCases = {"Bucket SSE": self.get_bucket_SSE_status, "Access Logging": self.get_access_logging_status, "Versioning": self.get_versioning_status, "Public Policy": self.is_bucket_public}


    def get_bucket_SSE_status(self):
        # S3 buckets can be encrypted at rest at two different levels, bucket and object.
        # Enabling default encryption at the bucket level will ensure objects created afterwards will be encrypted by the default key
        # However, if default encryption isn't enabled, objects can be created with encryption specification in the PUT request. Object encrypted, bucket not.
        # If default encryption is enabled at the bucket level after objects are created, these objects will not be encrypted.
        # It is necessary to check both the bucket and the object level for encryption.


        for buckets in self.s3client.list_buckets()['Buckets']:
            if 'isengard' and 'cloudTrail' not in buckets['Name'].lower():
                try:
                    self.s3client.get_bucket_encryption(Bucket=buckets)
                except Exception as e:
                    finding = buckets['Name']
                    self.results['Findings']['SSE_DISABLED'].append(finding)


    def get_object_SSE_status(self):
        for buckets in  self.s3client.list_buckets()['Buckets']:
            if 'isengard' and 'cloudtrail' not in buckets['Name'].lower():
                try:
                    for objects in self.s3client.list_objects(Bucket=buckets['Name'])['Contents']:
                         print(objects['Key'])
                         for config in self.s3client.get_object(Bucket=buckets['Name'], Key=objects['Key']):  # Check for SSE key 'ServerSideEncryption' or 'x-amz-server-side-encryption'
                             pass
                except Exception as e:
                    pass

    def get_access_logging_status(self):

        for buckets in self.s3client.list_buckets()['Buckets']:
            if 'isengard' and 'cloudTrail' not in buckets['Name'].lower():
                if self.s3client.get_bucket_logging(Bucket=buckets['Name']).get('LoggingEnabled') is None:
                    finding = buckets['Name']
                    self.results['Findings']['AccessLoggingDisabled'].append(finding)


    def get_versioning_status(self):

        for buckets in self.s3client.list_buckets()['Buckets']:
            if 'isengard' and 'cloudTrail' not in buckets['Name'].lower():
               try:
                  if self.s3client.get_bucket_versioning(Bucket=buckets['Name'])['Status'] != 'Enabled':  # Odd situation here where two cases are signal of versioning disabled:
                      finding = buckets['Name']
                      self.results['Findings']['VersioningDisabled'].append(finding)
               except Exception as e:
                   finding = buckets['Name']
                   self.results['Findings']['VersioningDisabled'].append(finding)


    def is_bucket_public(self):

        for buckets in self.s3client.list_buckets()['Buckets']:
            try:
                if self.s3client.get_bucket_policy_status(Bucket=buckets['Name'])["PolicyStatus"]["IsPublic"] == True:
                    finding =  buckets['Name']
                    self.results['Findings']['PublicBucket'].append(finding)
            except Exception as e:
                pass

    def audit(self):

        client = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results

    def results_to_html(self, results):
        html = ["<br><br><center><h1>S3 Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">Buckets</th>",
                "<th scope=\"col\"></th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html


class sqsAuditor(Auditor):

    def __init__(self, session):
        super().__init__(session, "sqs")
        self.sqs_client = self.get_client()
        self.results = {'Findings': {'SSE_DISABLED': []}}
        self.queues = self.sqs_client.list_queues()['QueueUrls']
        self.testCases = {'Queue SSE': self.sqs_sse_check}


    def sqs_sse_check(self):
        for qs in self.queues:
            try:  #  Behavior analysis: when boto3 client makes the API call to return a queue attribute that doesn't exist, the client errors out. KMS key doesn't exist == SSE disables
                 self.sqs_client.get_queue_attributes(Queueurl=self.queues, AttributeNames=['KmsMasterKeyId'])['Attributes']
            except Exception as e:
                 finding = qs
                 self.results['Findings']['SSE_DISABLED'].append(finding)

    def audit(self):
        client = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results

    def results_to_html(self, results):
        html = ["<br><br><center><h1>SQS Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">Queue URL</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            #html.append("<tr><th scope=\"row\">%s</th></th>" % findings)
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html

    def generate_markdown(self):
        pass
        #for finding in self.results


class lambdaAuditor(Auditor):

    def __init__(self, session):
        super().__init__(session, "lambda")
        self.lambdaClient = self.get_client()
        self.results = {'Findings': {'ENV_VARIABLES': []}}
        self.testCases = {'Env Variables': self.env_check}


    def env_check(self):

        with open("aws_words") as wordlist:
            words = wordlist.read().splitlines()
        for functions in self.lambdaClient.list_functions()["Functions"]:
            if "Environment" in functions.keys():
                for badword in words:
                    for variables in functions["Environment"]["Variables"]:
                        if badword in variables:
                            finding = {functions["FunctionArn"]: {'Interesting word "'+ badword +'" found in environment variables': functions["Environment"]["Variables"]}}
                            self.results['Findings']['ENV_VARIABLES'].append(finding)


    def audit(self):
        lambdaClient = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results

    def results_to_html(self, results):
        html = ["<br><br><center><h1>Lambda Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">Function Name</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            #html.append("<tr><th scope=\"row\">%s</th></th>" % findings)
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html


class apiAuditor(Auditor):

   def __init__(self, session):
       super().__init__(session, "apigateway")
       self.gatewayClient = self.get_client()
       self.results = {'Findings': {'PUBLIC_API': []}}
       self.testCases = {'Externally accessible APIs': self.public_endpoint}


   def public_endpoint(self):
       for apis in self.gatewayClient.get_rest_apis()['items']:
           if apis['endpointConfiguration'] != 'Private':
               finding = apis['name']
               self.results['Findings']['PUBLIC_API'].append(finding)


   def audit(self):
       apiClient = self.get_client()
       for cases in self.testCases:
           self.testCases[cases]()

       for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
       return self.results

   def results_to_html(self, results):
       html = ["<br><br><center><h1>API Gateway Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">API Name</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>",
               "<tbody>"
                ]
       for findings in results["Findings"]:
            #html.append("<tr><th scope=\"row\">%s</th></th>" % findings)
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
       html.append("</table><br><br>")
       return html



class kmsAudtior(Auditor):
    def __init__(self, session):
        super().__init__(session, "kms")
        self.kmsClient = self.get_client()
        self.results = {'Findings': {'KEY_ROTATION_DISABLED': []}}
        self.testCases = {'Key Rotation Disabled': self.key_rotation}


    def key_rotation(self):
        #Key rotation is enabled by default for AWS owned and managed CMKs
        #Key rotation should be done automatically every year.
        for key in kmsclient.list_keys()["Keys"]:
            if not kmsclient.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]:
                self.results['Findings']['KEY_ROTATION_DISABLED'].append(key["KeyId"])

    def audit(self):
        kmsClient = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
                return self.results

    def results_to_html(self, results):
        html = ["<br><br><center><h1>KMS Results</h1></center>",
                "<div class= \"container\">",
                "<div class=\"table-responsive\">",
                "<table class=\"table table-dark\" id=\"findings\">",
                "<thead><tr>",
                "<th scope=\"col\">Finding</th>",
                "<th scope=\"col\">Key ID</th>",
                "<th scope=\"col\">Report</th>",
                "</tr></thead>","<tbody>"
                ]
        for findings in results["Findings"]:
            if (type(results["Findings"][findings]) is list):
                html.append("<tr><td rowspan=\"{}\">{}</td>".format(len(results["Findings"][findings])+1, findings))
                for finding in results["Findings"][findings]:
                    html.append("<td>%s</td</tr>" % "".join(finding))
                    html.append("<td><button type=\"button\">Generate</button></td></tr>")
                html.append("<td><button type=\"button\">Generate For All {} Findings</button></td></tr>".format(findings))
            else:
                html.append("<td>%s</td>" % " ".join(results["Findings"][findings]))
                html.append("<td><button type=\"button\">Generate Forge Report</button></td>")
        html.append("</table><br><br>")
        return html


class customerAuditor(Auditor):

    def __init__(self, session):
        super().__init__(session, "customer_settings")
        self.results = {'Findings': {'MFA_DISABLED': [], 'WEAK_PW_COMPLEXITY': [], 'DANEROUS_USERS': []}}


    def mfa_check(self):
        pass

    def pw_complexity_check(self):
        pass

    def user_breack_check(self):
        # Check if I can find a free API like troy hunt's haveibeenpwned so I can pull all of the users from the customer account and run them through the API to see if they have been found in a breach
        # This should be flagged as a warning. Possibly use a username/email/password that hasn't been found in a breach
        pass


    def audit():
        customerClient = self.get_client()
        for cases in self.testCases:
            self.testCases[cases]()

        for services in self.results["Findings"].copy():
            if len(self.results["Findings"][services]) == 0:
                del self.results["Findings"][services]
        return self.results

    def results_to_html(self, results):
        html = ["<h1>Customer Results", "<table>"]
        for result in results:
            html.append("<tr><td>%s</td></tr>" % result)
        html.append("</table>")
        return "\n".join(html)

class AuditManager:
    def __init__(self, profile="default", region="us-east-1"):
        self.profile = profile
        self.region = region
        self.auditors =  {"ec2": ec2Auditor, "sns": snsAuditor, "s3": s3Auditor, "sqs": sqsAuditor, "lambda": lambdaAuditor, "apigateway": apiAuditor,"cloudfront": cloudFrontAuditor}
        self.results = {}
        self.html = []

    def get_session(self):
        return boto3.session.Session(region_name=self.region, profile_name=self.profile)

    def run_audits_service(self):
        session = self.get_session()
        for service in self.auditors:
            auditor = self.auditors[service](session)
            self.results[service] = auditor.audit()

    def run_audits_customer(self):

        session = self.get_session()
        self.auditors['customer'] = customerAuditor
        for services in  self.auditors:
            auditor = self.auditors[service](session)
            self.results[service] = auditor.audit()


    def generate_report(self):
        session = self.get_session()
        for result in self.results:
            auditor = self.auditors[result](session)
            self.html.append(auditor.results_to_html(self.results[result]))
        return self.html

    def get_results(self):
        return self.results


# Eventually move this to an CLI/driver class
# run against default profile and default region
am = AuditManager()
am.run_audits_service()

print(am.generate_report())
#results = am.get_results()  # Returns a dictionary of results. Keys are service names
#print(am.get_results().keys())
#print(json.dumps(am.get_results(), indent=2))

#keys = am.get_results().keys()
#print(keys)
#print(type(keys))
#for services in am.get_results():
#    print(services)





#with open('data.json', 'w') as findingoutput:
 #   json.dump(am.get_results(), findingoutput)


# TODO useful leter, this will return all SSE findings

#ssefindings = []
#for services in results:
#    try:
#        for finding in results[services]["Findings"]["SSE_DISABLED"]:
#            ssefindings.append(finding)
#    except Exception as e:
#        pass
#print(ssefindings)
#print(str(len(ssefindings)) + " SSE disabled findings")


#for services in results:
 #   print(results[services]["Findings"].keys())



# TODO try changing to results["Findings"]
#gen = generator(results)
#gen.generate_report()



#print(gen.printdata())


#gen = Generator(am.get_results())

# run against default region but under a different profile
#am = AuditManager(profile="default")
#am.run_audits()

# run against default profile but other region
#am = AuditManager(region="us-east-1")
#am.run_audits()
