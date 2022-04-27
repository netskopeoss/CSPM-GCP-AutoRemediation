usecase_name="GetNetskopeCSPM- CIS-1-0-0-1-4-ServiceAccountAdminPrivileges CIS-1-0-0-1-6-UserManagedKeyRotation CIS-1-0-0-2-1-CloudAuditLogging CIS-1-0-0-3-9-VPCFlowlogEnable CIS-1-0-0-3-1-DefaultVPCNetwork CIS-1-0-0-3-6-RestrictSSHAccess CIS-1-0-0-4-2-VMInstanceProjectWideSSHKeys CIS-1-0-0-5-1-StorageBucket CIS-1-0-0-6-2-CloudSQL CIS-1-0-0-6-1-CloudSQL CIS-1-0-0-7-1-KubernetesStackDriverLogging CIS-1-2-0-1-6-ServiceAccount"
region=$1

for name in $usecase_name; do
    service_account_name=$(echo $name | sed 's#[^-]*$##' | tr '[:upper:]' '[:lower:]')
    service_account_name="$service_account_name$region"
    gcloud iam service-accounts create $service_account_name --display-name $service_account_name
done
