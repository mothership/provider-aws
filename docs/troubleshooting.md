---
title: Troubleshoot
toc: true
weight: 160
indent: true
---
# Troubleshooting

## General Kubernetes debugging

General help on debugging applications running in Kubernetes can be found in the [Troubleshoot Applications task doc](https://kubernetes.io/docs/tasks/debug-application-cluster/debug-application/).

## Logs

The first place to look for more details about any issue with Crossplane would be its logs:

```console
kubectl -n crossplane-system logs -f $(kubectl -n crossplane-system get pod -l app=crossplane -o jsonpath='{.items[0].metadata.name}')
```

## Targeting Google Cloud Platform (GCP)

Crossplane runs in any Kubernetes control plane and it is possible to target and manage environments external to the control plane it is running in.
In order to manage resources in GCP, you must provide credentials for a GCP service account that Crossplane can use to authenticate.
Normally, you don't need to create a brand new GCP key.
Instead, just obtain an existing key from a system administrator.

### Configure gcloud

Find the name of your desired GCP project and then set it as the `gcloud` default:

```bash
gcloud config set project [your-project]
export PROJECT_ID=$(gcloud config get-value project)
```

### Create Service Account

After configuring `gcloud`, the service account must be created, you can skip this step is you are reusing an existing account.

```bash
# optional, skip this if the account has already been created
gcloud iam service-accounts create crossplane-gcp-provider --display-name "crossplane-gcp-provider"
```

### Create Service Account Key File

Next create a local file called `crossplane-gcp-provider-key.json` with all the credentials information stored in it.

```bash
gcloud iam service-accounts keys create crossplane-gcp-provider-key.json --iam-account crossplane-gcp-provider@${PROJECT_ID}.iam.gserviceaccount.com
```

### Bind Roles to Service Account

Currently, Crossplane requires only one role for its operations, this list will continue to expand as support for new resources is added.

* CloudSQL Admin: Full management of Cloud SQL instances and related objects.

```bash
gcloud projects add-iam-policy-binding ${PROJECT_ID} --member "serviceAccount:crossplane-gcp-provider@${PROJECT_ID}.iam.gserviceaccount.com" --role "roles/cloudsql.admin"
```

### (Optional) GCP Service Account Secret

If the example you are walking through does not create a Kubernetes secret, you can create one yourself now that you have obtained the service account JSON key file:

```bash
# optional, skip if the example does this for you
kubectl -n crossplane-system create secret generic gcp-service-account-creds --from-file credentials.json=crossplane-gcp-provider-key.json
```

## GKE RBAC

On GKE clusters, the default cluster role associated with your Google account does not have permissions to grant further RBAC permissions.
When running `make deploy`, you will see an error that contains a message similar to the following:

```console
clusterroles.rbac.authorization.k8s.io "crossplane-manager-role" is forbidden: attempt to grant extra privileges
```

To work around this, you will you need to run a command **one time** that is **similar** to the following in order to bind your Google credentials `cluster-admin` role:

```console
kubectl create clusterrolebinding dev-cluster-admin-binding --clusterrole=cluster-admin --user=<googleEmail>
```

## Targeting Microsoft Azure

In order to manage resources in Azure, you must provide credentials for a Azure service principal that Crossplane can use to authenticate.
This assumes that you have already [set up the Azure CLI client](https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli?view=azure-cli-latest) with your credentials.

Create a JSON file that contains all the information needed to connect and authenticate to Azure:

```console
# create service principal with Owner role
az ad sp create-for-rbac --sdk-auth --role Owner > crossplane-azure-provider-key.json
```

Save the `clientID` value from the JSON file we just created to an environment variable:

```console
export AZURE_CLIENT_ID=<clientId value from json file>
```

Now add the required permissions to the service principal we created that allow us to manage the necessary resources in Azure:

```console
# add required Azure Active Directory permissions
az ad app permission add --id ${AZURE_CLIENT_ID} --api 00000002-0000-0000-c000-000000000000 --api-permissions 1cda74f2-2616-4834-b122-5cb1b07f8a59=Role 78c8a3c8-a07e-4b9e-af1b-b5ccab50a175=Role

# grant (activate) the permissions
az ad app permission grant --id ${AZURE_CLIENT_ID} --api 00000002-0000-0000-c000-000000000000 --expires never
```

You might see an error similar to the following, but that is OK, the permissions should have gone through still:

```console
Operation failed with status: 'Conflict'. Details: 409 Client Error: Conflict for url: https://graph.windows.net/e7985bc4-a3b3-4f37-b9d2-fa256023b1ae/oauth2PermissionGrants?api-version=1.6
```