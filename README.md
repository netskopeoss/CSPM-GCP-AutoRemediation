# CSPM-GCP-AutoRemediation – CSPM security violation findings Auto-Remediation framework for GCP
## Overview

In this article we’ll demonstrate how you can implement automatic remediation for security posture violation findings discovered by Netskope Cloud Security Posture Management (CSPM).



Netskope CSPM continuously assesses public cloud deployments to mitigate risk, detect threats, scan and protect sensitive data and monitor for regulatory compliance. Netskope simplifies the discovery of security misconfigurations across your clouds. Netskope Auto-Remediation framework for GCP enables you to automatically mitigate the risk associated with these misconfigurations in your GCP cloud environment.



Netskope CSPM security assessment results for such security benchmark standards as NIST, CIS, PCI DSS, as well as for your custom rules are available via the [View Security Assessment Violations Netskope API](https://docs.netskope.com/en/view-security-assessment-violations.html).

Netskope auto-Remediation solution for GCP deploys the set of GCP Cloud functions that query the above Netskope API on the scheduled intervals and mitigates supported violations automatically.

You can deploy the framework as is or customize it to mitigate other security violations and to meet your specific organization’s security requirements.





## Auto-remediation Workflow
# ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.001.png)

**Workflow Overview:**

- Cloud scheduler will trigger Pub/Sub(1) topic with payload/message after every interval.
- Payload/message will have two parameters:
1. rule\_name: Name of the Rule for which remediation is required.
1. rule\_short\_name: This will be the Pub/Sub(2) topic name that will be used by GetNetskopeCSPMResults Cloud Function to push alert details to Remediation Cloud Function.
- Pub/Sub(1) will trigger the GetNetskopeCSPMResults cloud function which will perform the below steps:
  - Pull payload/message from pub/sub(1) topic.
  - Call Netskope Security Assessment Violation API for given rule\_name. If the rule is violated then, extract parameters GCP ProjectID, Resource ID, and Region Name from the alert.
  - Trigger Pub/Sub(2) topic and push extracted parameters. Pub/Sub(2) topic will pass these parameters to the Remediation cloud function of specified rule\_name.
- The remediation cloud function will pull information from Pub/Sub(2) and perform remediation.
- Check logs of remediation functions in cloud logging.

## Prerequisites

- To deploy Auto-remediation on the GCP platform, a logged-in user should either have the Service Account Admin or Organization Administrator role.
- GCP Project is required to deploy auto-remediation resources
## Deployment Plan: 

1. Create a Service Account. 
   1. For remediating violations of resources, remediator google functions need Service Account to perform actions on your behalf.
1. Create a Role
   1. The role contains a set of permissions to perform actions on Google Cloud resources. Service Account needs a role grant to perform actions.
1. Add the service account under project ID
   1. In order to perform remediation actions on Google Project Resources either you need to bind the service account with a role at each project, folder, or organization
1. Create Secrets for Netskope Tenant Credentials in Secrets Manager
   1. To fetch violations from Netskopt Tenant, the fetcher API credentials will be stored in Google Cloud Secrets Manager
1. Create Cloud Functions
   1. Google Cloud functions will be responsible for fetching and remediating resource violations
1. Create Cloud Scheduler 
   1. After every specified interval cloud scheduler will publish a message to the [Pub/Sub Topic](https://cloud.google.com/pubsub/docs/overview#:~:text=Core%20concepts-,Topic,-.%20A%20named%20resource) which triggers Google Cloud Function that will fetch violations and give them to the remediator Google Cloud Functions.
##
## GCP Auto-remediation Deployment Steps
Log in to console.cloud.google.com.
### **1. Create a Service Account:**

**GCP Portal Steps**

1. From the top navigation bar of the Google Cloud Platform home page, click the drop-down list and select the appropriate project under which you need to deploy an Auto-remediation solution.


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.002.png)

1. Click the top-left hamburger navigation menu and navigate to IAM & admin > Service accounts. The Service accounts page opens.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.003.png)

1. Click + CREATE SERVICE ACCOUNT  
   The Create service account right pane opens.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.004.png)

1. In the Service account details section, enter the following details:
   1. In the Service account name field, enter the name of the service account ex: cis-1-0-0-1-4-us-east1. Please refer “[Name Preferences for Use cases](#_ymmhl6snxvah)” table 
   1. The service account ID mirrors the service account name. Optionally, you can edit the service account ID.
   1. In the Service account description field, enter a short description.


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.005.png)

1. Click CREATE.
1. Repeat above steps to create a service account for each use case.

**Alternatively, multiple service accounts can be created using shell script by following the below steps:** 


1. Install [GCloud CLI](https://cloud.google.com/sdk/docs/install) in your local machine.  
1. Once installed, Open the terminal  
1. Set a default project by executing the below command in the terminal:
   1. ##### gcloud config set project <PROJECT\_NAME>
1. Check your configuration using below command:
   1. ##### gcloud config list
1. Run the create\_service\_accounts Bash script file to Create service accounts:

Open auto-remediation root directory, Go to GCPShellScript > service-accounts

1. ##### sh create\_service\_accounts.sh <REGION\_NAME> 

**Note:** If you run this command then it will create service accounts for all use cases.
### **2. Create a Role:** 
You should add the roles to those project IDs that require Auto-remediation. You can add the roles to multiple project IDs. If you have a requirement of Auto-remediation to all the projects under your folder or organization, you should add the roles at the folder or organization level.

**Steps**

1. From the top navigation bar of the Google Cloud Platform home page, click the drop-down list and select the project ID that requires Auto-remediation.


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.002.png)

1. Click the top-left hamburger navigation menu and navigate to IAM & admin > Roles.


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.006.png)

1. Click + CREATE ROLE. The Create role right pane opens

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.007.png)

1. In the roles details section, enter the following details:
   1. In the roles Title field, enter the title of the role ex: CIS-1-0-0-1-4-ServiceAccountAdminPrivilegesRole-us-east1.Please refer “[Name Preferences for Use cases](#_ymmhl6snxvah)” table 
   1. Edit the role id on the base of the name. Ex: CIS10014ServiceAccountAdminPrivilegesRoleuseast1.
   1. In the roles description field, enter a short description.
   1. Choose Alpha in the Role launch stage
1. Click ADD PERMISSIONS

The Add Permissions modal opens

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.008.png)

1. Select all required permissions for the particular use case. Please refer to the use case documentation for a list of permissions.
1. Click ADD on Add Permissions modal.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.009.png)

1. Click CREATE.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.010.png)

1. Repeat above steps to create a role for each use case.


**Alternatively, multiple roles can be created using shell script by following below steps:** 

1. Install [jq](https://stedolan.github.io/jq/download/) and [GCloud CLI](https://cloud.google.com/sdk/docs/install) in your local machine by following their documentation. 
1. Open terminal
1. Set a default project by executing the below command in the terminal:

1. ##### gcloud config set project <PROJECT\_NAME>
#####
1. Check your configuration using below command:
   1. ##### gcloud config list
1. Run the create\_iam\_role Bash script file to Create Roles:  

Open auto-remediation root directory, Go to GCPShellScript > roles

1. ##### sh create\_iam\_role.sh <REGION\_NAME> 
**Note:** If you run this command then it will create roles for all the use cases.

### **3. Add Service Account under Project ID:** 
You should add the service account as an IAM user to those project IDs that require Auto-remediation. You can add the service account to multiple project IDs. If you have a requirement of Auto-remediation to all the projects under your folder or organization, you should add the service account at the folder or organization level.

1. From the top navigation bar of the Google Cloud Platform home page, click the drop-down list and select the project where you have created the service account.

   ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.002.png)
1. Click the top-left hamburger navigation menu and navigate to IAM & admin > Service accounts.

The Service accounts page opens.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.003.png)

1. On the Service account page, locate the service account you created in the first step and note down the email address.



   ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.011.png)
1. Click the top-left hamburger navigation menu and navigate to IAM & admin > Roles. System will list down roles created for selected project.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.006.png)

1. On the Roles page, locate the role you created in the second step and note down the name.

   ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.012.png)
1. On the top left of the Google Cloud Platform home page, click the drop-down list and select the project ID that requires Auto-remediation.
1. Click the top-left hamburger navigation menu and navigate to IAM & admin > IAM.

The IAM page opens.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.013.png)

1. On the IAM page, click + ADD to add the service account user.

The Add members right pane opens.

1. In the New member's field, enter the email address that you noted.
1. Under the Select Role drop down, select the role which you noted.

   ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.014.png)
1. Click SAVE.

**Note: Repeat the above procedure to add the service account to other project IDs.**

### **4.  Create Secrets for Netskope Tenant Credentials in Secrets Manager** 
1. From the top navigation bar of the Google Cloud Platform home page, click the drop-down list and select the project where you have to store the tenant information
1. Search Secret Manager in center located search bar
1. select Secret Manager from search result

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.015.png)

1. Click on CREATE SECRET located at top menu

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.016.png)

1. Provide Secret name **NetskopeTenantFQDN** for the tenant FQDN
1. Provide Netskope tenant FQDN value in Secret Value textbox
1. Click on Create Secret

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.017.png)

1. Find **NetskopeAPIToken** by going to Settings > Tools >  REST API V1 >Token** of Netskope tenant for which you want to configure remediation
1. Create another secret for Netskope API Token by following the above mentioned steps and provide secret name **NetskopeAPIToken** and its value


### **5. Create Cloud Functions:**

1. From the top navigation bar of Google Cloud Platform home page, click the drop-down list and select the appropriate project under which you need to deploy an Auto-remediation solution.
1. Click the top-left hamburger navigation menu and navigate to Cloud Functions.

The Cloud Functions page opens.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.018.png)

1. Click on + Create Function
1. In the Basics details section, enter the following details:
   1. Enter a Function Name. 

ex: CIS-1-0-0-1-4-ServiceAccountAdminPrivilege-us-east1. Please refer “[Name Preferences for Use cases](#_ymmhl6snxvah)” table 

1. Choose a region for which you want to deploy auto remediation from region dropdown.


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.019.png)

1. In the Trigger details section, enter the following details:
   1. Under Trigger type dropdown Please choose Cloud Pub/Sub

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.020.png)

1. Under a **Select a Cloud Pub/Sub Topic** dropdown Click CREATE A TOPIC.
   1. Please add a Topic ID and click on Create Topic. Please refer “[Name Preferences for Use cases](#_ymmhl6snxvah)” table 


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.021.png)

1. Click on SAVE.
1. Open Runtime, build, connections, and security settings
   1. Set Timeout parameter to 300 (5 minutes) (Increase this parameter value for the use case if you face function timeout issues)
   1. In the Runtime service account dropdown select a service account that you have created for the particular use case.
   1. You can set Environment Variable **LOGLEVEL** to INFO by default it is DEBUG
      ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.022.png)
1. Click on NEXT.
1. In the Code section, enter the following details:
   1. In the runtime dropdown please select **“python3.7”**
   1. For Entry points please add “**google\_cloud\_function\_handler”**


**![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.023.png)**


1. In Source code please select Zip Upload
   1. In Zip File click on BROWSE and select zip from your local machine for the particular use case. (Zip can be found from Github Repo of GCP auto-remediation)
   1. In Stage Bucket click on BROWSE
      1. Select a particular bucket and folder where you want to store the source code of Cloud Functions (If you don’t have a bucket please create the same and use it)


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.024.png)

1. Click DEPLOY
### **6. Create Cloud Scheduler:**

1. From the top navigation bar of the Google Cloud Platform home page, click the drop-down list and select the appropriate project under which you need to deploy an Auto-remediation solution.
   ![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.002.png)
1. Click the top-left hamburger navigation menu and navigate to Cloud Scheduler.

The Cloud Scheduler page opens.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.025.png)

1. Click on CREATE A JOB
1. In Define the schedule section, enter the following details
   1. Enter a Scheduler Name. 

ex: CIS-1-0-0-1-4-ServiceAccountAdminPrivilege-us-east1

Please refer “[Name Preferences for Use cases](#_ymmhl6snxvah)” table 

1. Choose a region from Region dropdown
1. In the description field, enter a short description.
1. In the Frequency field, You can define a schedule so that your Function runs multiple times a day, or runs on specific days and months.

If you want to run remediation every 3 Hours so you can set it as 

**\* \*/3 \* \* \***

1. In the Timezone dropdown please select a respective Time Zone on the basis of the requirement.

![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.026.png)

1. In ​​Configure the execution section, enter the following details
   1. In Target type dropdown select Pub/Sub
   1. In Select a Cloud Pub/Sub Topic please select Topic which you created for the Get CSPM Alert Function.
   1. In Message attributes please add the following keys:
      1. **rule\_name**: Please refer to the document for the rule\_name of a particular use case.
      1. **rule\_short\_name**: It should be the same as Topic ID which we have created at the time of Function Creation. 


![](.//media/GCP-autoremediation.a6f08a78-7dbe-4ad8-8fe4-182f022272e4.027.png)

1. Click CREATE

**Note: Repeat all the above procedures to add more use cases for all regions on which you need Auto-remediation. Deployment of Auto-Remediation is region specific.**
## Name Preferences for Use cases


|**Use case**|**Role**|**Service Account**|**Cloud Function**|**Cloud Scheduler**|**Pub/Sub Topic**|**Permissions Required**|
| :- | :- | :- | :- | :- | :- | :- |
|Get Netskope Alert Function|GetNSPAAlertsRole-<Region>|GetNSPAAlerts<Region>|GetNSPAAlertsFunction-<Region>|GetNSPAAlertsScheduler-<Region>|GetNSPAAlerts-<Region>|<p>pubsub.topics.publish</p><p></p><p>secretmanager.versions.access</p><p></p>|
|Communications and control network protection: Ensure the default network does not exist in a project|CIS-1-0-0-3-1-DefaultVPCNetworkRole-<Region>|CIS-1-0-0-3-1-<Region>|[CIS-1-0-0-3-1-DefaultVPCNetworkRemediation](https://bitbucket.org/crestdatasys/netskope-auto-remediation/src/develop/GCP/GoogleFunctions/DefaultVPCNetworkRemediationFunction/CIS-1-0-0-3-1-DefaultVPCNetworkRemediationFunction.zip)-<Region>|CIS-1-0-0-3-1-[DefaultVPCNetwork](https://bitbucket.org/crestdatasys/netskope-auto-remediation/src/develop/GCP/GoogleFunctions/DefaultVPCNetworkRemediationFunction/CIS-1-0-0-3-1-DefaultVPCNetworkRemediationFunction.zip)Scheduler-<Region>|CIS-1-0-0-3-1-<Region>|<p>compute.networks.delete</p><p></p><p>compute.globalOperations.get</p><p></p><p></p>|
|Remote access: Ensure "Block Project-wide SSH keys" enabled for VM instances|CIS-1-0-0-4-2-VMProjectWideSSHKeysRole-<Region>|CIS-1-0-0-4-2-<Region>|CIS-1-0-0-4-2-VMBlockProjectWideSSHKeysRemediation-<Region>|CIS-1-0-0-4-2-VMBlockProjectWideSSHKeysScheduler-<Region>|CIS-1-0-0-4-2-<Region>|<p>compute.instances.get</p><p></p><p>compute.instances.setMetadata</p><p></p><p>compute.zoneOperations.get</p><p></p><p>iam.serviceAccounts.actAs</p><p></p><p></p>|
|Identities and credentials: Ensure user-managed/external keys for service accounts are rotated every 90 days or less|Service Account Key Admin (Use In-buit Role)|App Engine default service account (Use default service account)|CIS-1-0-0-1-6-UserManagedKeyRotationRemediation-<Region>|<p>CIS-1-0-0-1-6-UserManagedKeyRotationScheduler-<Region></p><p></p>|CIS-1-0-0-1-6-<Region>|-|
|Identities and credentials: Ensure that ServiceAccount has no Admin privileges.|CIS-1-0-0-1-4-ServiceAccountAdminPrivilegesRole-<Region>|CIS-1-0-0-1-4-<Region>|CIS-1-0-0-1-4-ServiceAccountAdminPrivilegesRemediation-<Region>|<p>CIS-1-0-0-1-4-ServiceAccountAdminPrivilegesScheduler-<Region></p><p></p>|CIS-1-0-0-1-4-<Region>|<p>resourcemanager.projects.getIamPolicy</p><p></p><p>resourcemanager.projects.setIamPolicy</p><p></p><p></p>|
|Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level|CIS-1-2-0-1-6-ServiceAccountRole-<Region>|CIS-1-2-0-1-6-<Region>|CIS-1-2-0-1-6-ServiceAccountRoleRemediation-<Region>|<p>CIS-1-2-0-1-6-ServiceAccountRoleScheduler-<Region></p><p></p>|CIS-1-2-0-1-6-<Region>|<p>resourcemanager.projects.getIamPolicy</p><p></p><p>resourcemanager.projects.setIamPolicy</p>|
|Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters|CIS-1-0-0-7-1-KubernetesStackDriverLoggingRole-<Region>|CIS-1-0-0-7-1--<Region>|CIS-1-0-0-7-1-KubernetesStackDriverLoggingRemediation-<Region>|CIS-1-0-0-7-1-KubernetesStackDriverLoggingScheduler-<Region>|CIS-1-0-0-7-1--<Region>|<p>container.clusters.get</p><p></p><p>container.clusters.update</p><p></p><p>container.operations.get</p><p></p><p></p>|
|Ensure that Cloud Audit Logging is configured properly across all services and all users from a project|CIS-1-0-0-2-1-CloudAuditLoggingRole-<Region>|<p>CIS-1-0-0-2-1--<Region></p><p></p>|<p>CIS-1-0-0-2-1-CloudAuditLoggingRemediation-<Region></p><p></p>|CIS-1-0-0-2-1-CloudAuditLoggingScheduler-<Region>|<p>CIS-1-0-0-2-1--<Region></p><p></p>|<p>resourcemanager.projects.getIamPolicy</p><p></p><p>resourcemanager.projects.setIamPolicy</p><p></p><p></p>|
|Identities and credentials: Ensure that Cloud SQL database Instances are not open to the world|CIS-1-0-0-6-2-CloudSQLInstancePublicNetworkRole-<Region>|CIS-1-0-0-6-2-<Region>|<p>CIS-1-0-0-6-2-CloudSQLInstancePublicNetworkRemediation-<Region></p><p></p>|CIS-1-0-0-6-2-CloudSQLInstancePublicNetworkScheduler-<Region>|<p>CIS-1-0-0-6-2-<Region></p><p></p>|<p>cloudsql.instances.get</p><p></p><p>cloudsql.instances.update</p><p></p><p></p>|
|Data-in-transit is protected: Ensure that Cloud SQL database instance requires all incoming connections to use SSL|<p>CIS-1-0-0-6-1-CloudSQLInstanceSSLConnectionRole-<Region></p><p></p>|<p>CIS-1-0-0-6-1-<Region></p><p></p>|<p>CIS-1-0-0-6-1-CloudSQLInstanceSSLConnectionRemediation-<Region></p><p></p>|CIS-1-0-0-6-1-CloudSQLInstanceSSLConnectionScheduler-<Region>|<p>CIS-1-0-0-6-1-<Region></p><p></p>|<p>cloudsql.instances.get</p><p></p><p>cloudsql.instances.update</p><p></p><p></p>|
|Identities and credentials: Ensure that Cloud Storage bucket is not anonymously or publicly accessible|CIS-1-0-0-5-1-StorageBucketPublicAccessRole-<Region>|<p>CIS-1-0-0-5-1-<Region></p><p></p>|<p>CIS-1-0-0-5-1-StorageBucketPublicAccessRemediation-<Region></p><p></p>|CIS-1-0-0-5-1-StorageBucketPublicAccessScheduler-<Region>|<p>CIS-1-0-0-5-1-<Region></p><p></p>|<p>storage.buckets.getIamPolicy</p><p></p><p>storage.buckets.setIamPolicy</p><p></p><p></p>|
|Ensure that SSH access is restricted from the internet|CIS-1-0-0-3-6-RestrictSSHAccessRole-<Region>|<p>CIS-1-0-0-3-6-<Region></p><p></p>|<p>CIS-1-0-0-3-6-RestrictSSHAccessRemediation-<Region></p><p></p>|CIS-1-0-0-3-6-RestrictSSHAccessScheduler-<Region>|<p>CIS-1-0-0-3-6-<Region></p><p></p>|<p>compute.firewalls.get</p><p></p><p>compute.networks.updatePolicy</p><p></p><p>compute.firewalls.delete</p><p></p><p>compute.globaloperations.get</p><p></p><p>compute.firewalls.update</p><p></p><p></p>|
|Communications and control network protection: Ensure VPC Flow logs is enabled for every subnet in VPC Network in VPC Network|CIS-1-0-0-3-9-VPCFlowlogEnableRole-<Region>|<p>CIS-1-0-0-3-9-<Region></p><p></p>|<p>CIS-1-0-0-3-9-VPCFlowlogEnableRemediation-<Region></p><p></p>|CIS-1-0-0-3-9-VPCFlowlogEnableScheduler-<Region>|<p>CIS-1-0-0-3-9-<Region></p><p></p>|<p>compute.subnetworks.list</p><p></p><p>compute.subnetworks.update</p><p></p><p>compute.subnetworks.get</p><p></p><p>compute.regionoperations.get</p><p></p><p>compute.networks.get</p>|



## Get Netskope Security Posture Assessment Alert Function
- **Description**
  - Function fetches the Security Assessments Alerts from CSPM tenant for each rule and publish it to pub/sub topic 

- **Permissions Required**
  - pubsub.topics.publish
  - Secretmanager.versions.access











Supported GCP Auto-remediation Rules



|<p>**Sr.**</p><p>**No.**</p>|**Profile**|**Service**|**Rule Name**|**Action**|
| :- | :- | :- | :- | :- |
|1|CIS-GCPFND-1.0.0|Compute Engine|Ensure the default network does not exist in a project|The auto-remediation cloud function deletes the default VPC network.|
|2|CIS-GCPFND-1.0.0|Compute Engine|Ensure "Block Project-wide SSH keys" enabled for VM instances|The auto-remediation cloud function set “block-project-ssh-keys” meta-data value of VM instance to True.|
|3|CIS-GCPFND-1.0.0|IAM|Identities and credentials: Ensure user-managed/external keys for service accounts are rotated every 90 days or less|The auto-remediation cloud function disables the Service Account keys that are created before 90 days|
|4|CIS-GCPFND-1.0.0|IAMPolicy|<p>Identities and credentials: Ensure that ServiceAccount has no Admin privileges.</p><p></p>|The auto-remediation cloud function removes Service Account entries from members for owner/editor/\*Admin role|
|5|CIS-GCPFND-1.2.0|Identity|Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level|The auto-remediation cloud function removes role binding from policy having role as “Service Account User” or “Service Account Token Creator”|
|6|CIS-GCPFND-1.0.0|Kubernetes|<p>Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters</p><p></p>|The auto-remediation cloud function set the logging service as “logging.googleapis.com/kubernetes” if not set|
|7|CIS-GCPFND-1.0.0|Logging|Ensure that Cloud Audit Logging is configured properly across all services and all users from a project|<p>The auto-remediation cloud function removes exempted members from audit logging service configurations and enable audit logging for all services with log types: DATA\_READ,  DATA\_WRITE, ADMIN\_READ, ADMIN\_WRITE</p><p></p>|
|8|CIS-GCPFND-1.0.0|SQL|Ensure that Cloud SQL database Instances are not open to the world|The auto-remediation cloud function removes a network which has an IP value of “0.0.0.0/0“ from Cloud SQL Instance.|
|9|CIS-GCPFND-1.0.0|SQL|Ensure that Cloud SQL database instance requires all incoming connections to use SSL|The auto-remediation cloud function set “requireSsl” property of cloud SQL instance to True.|
|10|CIS-GCPFND-1.0.0|Storage|Identities and credentials: Ensure that Cloud Storage bucket is not anonymously or publicly accessible|The auto-remediation cloud function removes “allUsers” and “allAuthenticatedUsers” principles from the bindings of bucket policy. |
|11|CIS-GCPFND-1.0.0|VPCnetwork|Ensure that SSH access is restricted from the internet|The auto-remediation cloud function removes the entry for source “0.0.0.0/0” from firewall rule source ranges if present|
|12|CIS-GCPFND-1.0.0|VPCnetwork|<p>Ensure VPC Flow logs is enabled for every subnet in VPC Network</p><p></p>|The auto-remediation cloud function enables flow logging for each subnet region-wise|


# Service: Compute Engine
1. ## Communications and control network protection: Ensure the default network does not exist in a project

- **Rule Definition**
  - VPC should not have Name eq "default" and AutoCreateSubnetworks eq True

- **Auto-Remediation Overview**
  - To prevent use of the default network, a project should not have a default network.The default network has automatically created firewall rules and has pre-fabricated network configuration. Based on your security and networking requirements, you should create your network and delete the default network.
  - The auto-remediation cloud function deletes the default VPC network.

- **Information from alert**
  - GCP Project ID
  - VPC Network ID
  - Region Name

- **Permissions Required**
  - compute.networks.delete
  - compute.globalOperations.get

1. ## Remote access: Ensure "Block Project-wide SSH keys" enabled for VM instances

- **Rule Definition**
  - Instance where not ( Name like "^gke-" and Tags with [ Name eq "goog-gke-node" and Value eq "" ] ) should have Metadata . Items with [ Key eq "block-project-ssh-keys" and Value like "[Tt][Rr][Uu][Ee]" ]

- **Auto-Remediation Overview**
  - Project-wide SSH keys are stored in Compute/Project-meta-data. Project wide SSH keys can be used to login into all the instances within project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.
  - The auto-remediation cloud function set “block-project-ssh-keys” meta data value of VM instance to True

- **Information from alert**
  - GCP Project ID
  - VM Instance ID
  - Region Name

- **Permissions Required**
  - compute.instances.get
  - compute.instances.setMetadata
  - compute.zoneOperations.get
  - iam.serviceAccounts.actAs
# Service: IAM
1. ## Identities and credentials: Ensure user-managed/external keys for service accounts are rotated every 90 days or less

- **Rule Definition**
  - ServiceAccount should have every Keys with [ Validity . AfterTime isLaterThan ( -90, "days" ) ]

- **Auto-Remediation Overview**
  - Service Account keys consist of a key ID (Private\_key\_Id) and Private key, which are used to sign programmatic requests that you make to Google cloud services accessible to that particular Service account. It is recommended that all Service Account keys are regularly rotated.
  - The auto-remediation cloud function disables the Service Account keys that are created before 90 days

- **Information from alert**
  - GCP Project ID
  - Service Account
  - Region Name

- **Permissions Required**
  - roles/iam.serviceAccountKeyAdmin (In-Built GCP Role, As there are no permissions related to disable the key in GCP. **Role may give more access permissions to service account**) 

# Service: IAMPolicy
1. ## Identities and credentials: Ensure that ServiceAccount has no Admin privileges.

- **Rule Definition**
  - IAMPolicy should not have Members . ServiceEmails with [ Email like "iam\.gserviceaccount\.com$" ]  and ( Role . id in ("roles/editor", "roles/owner") or Role . id like ".\*Admin$" )

- **Auto-Remediation Overview**
  - ServiceAccount with Admin rights gives full access to an assigned application or a VM. A ServiceAccount Access holder can perform critical actions, such as delete and update change settings, without user intervention.
  - The auto-remediation cloud function removes Service Account entries from members for owner/editor/\*Admin role

- **Information from alert**
  - GCP Project ID
  - Role Name
  - Region Name

- **Permissions Required**
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.projects.setIamPolicy
#
# Service: Identity
1. ## Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level

- **Rule Definition**
  - IAMPolicy where Name eq "iam.serviceAccountUser" or Name eq "iam.serviceAccountTokenCreator" should have Members . UserEmails len() eq 0

- **Auto-Remediation Overview**
  - User having Service Account User or Service Account Token Creator role, can manage all the service accounts which lead to misuse of resources
  - The auto-remediation cloud function removes role binding from policy having role as “Service Account User” or “Service Account Token Creator”

- **Information from alert**
  - GCP Project ID
  - Role Name
  - Region Name

- **Permissions Required**
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.projects.setIamPolicy
# Service: Kubernetes
1. ## Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters

- **Rule Definition**
  - KubernetesCluster should have LoggingService in ( "logging.googleapis.com", "logging.googleapis.com/kubernetes")

- **Auto-Remediation Overview**
  - Stackdriver Logging lets you have Kubernetes Engine automatically collect, process, and store your container and system logs in a dedicated, persistent datastore.
  - The auto-remediation cloud function set the logging service as “logging.googleapis.com/kubernetes” if not set

- **Information from alert**
  - GCP Project ID
  - Kubernetes Cluster Name
  - Region Name

- **Permissions Required**
  - container.clusters.get
  - container.clusters.update
  - container.operations.get
# Service: Logging
1. ## Ensure that Cloud Audit Logging is configured properly across all services and all users from a project

- **Rule Definition**
  - GCP should have atleast one AuditConfigs with [ Service eq "allServices" and AuditLogConfigs with [ LogType eq "DATA\_READ" ] and AuditLogConfigs with [ LogType eq "DATA\_WRITE" ] and AuditLogConfigs with [ LogType eq "ADMIN\_READ" ] ] and every AuditConfigs with [ HasExemptedMembers eq False ]

- **Auto-Remediation Overview**
  - Cloud Audit Logging helps recording administrative activities and accesses within your Google Cloud resources
  - The auto-remediation cloud function removes exempted members from audit logging service configurations and enable audit logging for all services with following log types
    - DATA\_READ
    - DATA\_WRITE
    - ADMIN\_READ
    - ADMIN\_WRITE

- **Information from alert**
  - GCP Project ID
  - GCP Project ID
  - Region Name

- **Permissions Required**
  - resourcemanager.projects.getIamPolicy
  - resourcemanager.projects.setIamPolicy


# Service: SQL
1. ## Identities and credentials: Ensure that Cloud SQL database Instances are not open to the world

1. **Rule Definition**
   1. SqlInstance should not have Settings . IpConfiguration . AuthorizedNetworks with [ CIDR eq 0.0.0.0/0 ]

1. **Auto-Remediation Overview**
   1. To minimize attack surface on a Database server Instance, only trusted/known and required IP(s) should be white-listed to connect to it. Authorized networks should not have IPs/networks configured to 0.0.0.0 or /0 which will allow access to the instance from anywhere in the world.
   1. The auto-remediation cloud function removes a network which has an IP value as 0.0.0.0/0 from Cloud SQL Instance.

1. **Information from alert**
   1. GCP Project ID
   1. Cloud SQL Instance ID
   1. Region Name

- **Permissions Required**
  1. cloudsql.instances.get
  1. cloudsql.instances.update

1. ## Data-in-transit is protected: Ensure that Cloud SQL database instance requires all incoming connections to use SSL

- **Rule Definition**
  - SqlInstance should have Settings . IpConfiguration . RequireSsl eq True

- **Auto-Remediation Overview**
  - SQL database connections if successfully trapped (MITM); can reveal sensitive data like credentials, database queries, query outputs etc. For security, it is recommended to always use SSL encryption when connecting to your instance
  - The auto-remediation cloud function set “requireSsl” property of cloud SQL instance to True.

- **Information from alert**
  - GCP Project ID
  - Cloud SQL Instance ID
  - Region Name

- **Permissions Required**
  - cloudsql.instances.get
  - cloudsql.instances.update
#
# Service: Storage
1. ## Identities and credentials: Ensure that Cloud Storage bucket is not anonymously or publicly accessible

- **Rule Definition**
  - Bucket should not have Policies with [ Members . AllUsers eq True or Members . AllAuthenticatedUsers eq True

- **Auto-Remediation Overview**
  - Allowing anonymous and/or public access grants permissions to anyone to access bucket content. Such access might not be desired if you are storing any sensitive data. Hence, ensure that anonymous and/or public access to a bucket is not allowed.
  - The auto-remediation cloud function removes “allUsers” and “allAuthenticatedUsers” principles from the bindings of bucket policy. 

- **Information from alert**
  - GCP Project ID
  - Bucket ID
  - Region Name

- **Permissions Required**
  - storage.buckets.getIamPolicy
  - storage.buckets.setIamPolicy




#
# Service: VPCnetwork
1. ## Ensure that SSH access is restricted from the internet

- **Rule Definition**
  - FirewallRule where Disabled eq False should not have Direction eq "INGRESS" and SourceRanges with [ Value eq 0.0.0.0/0 ] and Allowed with [ Protocol in ("all", "tcp") and Ports with [ FromPort lte 22 and ToPort gte 22 ]

- **Auto-Remediation Overview**
  - This route simply defines the path to the Internet, to avoid the most general (0.0.0.0/0) destination IP Range specified from Internet through SSH with default Port 22 assigned to google cloud firewall rule. We need to restrict generic access from the Internet to specific IP Range.
  - The auto-remediation cloud function removes the entry for source “0.0.0.0/0” from firewall rule source ranges if present

- **Information from alert**
  - GCP Project ID
  - Firewall Rule Name
  - Region Name

- **Permissions Required**
  - compute.firewalls.get
  - compute.networks.updatePolicy
  - compute.firewalls.delete
  - compute.globaloperations.get
  - compute.firewalls.update

1. ## Ensure VPC Flow logs is enabled for every subnet in VPC Network

- **Rule Definition**
  - VPC should have every Subnetworks with [ LogEnabled ]

- **Auto-Remediation Overview**
  - Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC Subnets. Flow Logs provide visibility into network traffic for each VM inside the subnet and can be used to detect anomalous traffic or insight during security workflows. It is recommended that Flow Logs be enabled for every business critical VPC subnet.
  - The auto-remediation cloud function enables flow logging for each subnet region-wise

- **Information from alert**
  - GCP Project ID
  - VPC Network Name
  - Region Name

- **Permissions Required**
  - compute.subnetworks.list
  - compute.subnetworks.update
  - compute.subnetworks.get
  - compute.regionoperations.get
  - compute.networks.get
