usecase_name="GetNetskopeCSPMResults CIS-1-0-0-1-4-ServiceAccountAdminPrivileges CIS-1-0-0-1-6-UserManagedKeyRotation CIS-1-0-0-2-1-CloudAuditLogging CIS-1-0-0-3-9-VPCFlowlogEnable CIS-1-0-0-3-1-DefaultVPCNetwork CIS-1-0-0-3-6-RestrictSSHAccess CIS-1-0-0-4-2-VMInstanceProjectWideSSHKeys CIS-1-0-0-5-1-StorageBucket CIS-1-0-0-6-2-CloudSQL CIS-1-0-0-6-1-CloudSQL CIS-1-0-0-7-1-KubernetesStackDriverLogging CIS-1-2-0-1-6-ServiceAccount"

region=$1

for name in $usecase_name; do
    role_name="${name}Role-$region"
    role_id=$(echo $role_name | sed 's/[^a-zA-Z 0-9]//g')
    perl -pi -e "s/changeme/$role_name/g" $name.json
    gcloud iam roles create $role_id --project=$(gcloud config list --format='json' | jq -r '.core.project') --file=$name.json
    perl -pi -e "s/$role_name/changeme/g" $name.json
done

