#!/usr/bin/bash

function check_current_dir() {
    if [[ ! $(echo $PWD | grep 'argocd-vault-plugin-demo/helpers') ]]; then
      echo "For the correct script execution, current dir \
must be 'argocd-vault-plugin-demo/helpers'. Aborting." >&2; exit 1;
    fi
}

function check_components_install() {
    components_array=("minikube" "kubectl" "helm")
    for i in "${components_array[@]}"; do
      command -v "${i}" >/dev/null 2>&1 ||
        { echo "${i} is required, but it's not installed. Aborting." >&2; exit 1; }
    done
}

function check_minikube_is_running() {
  minikube profile list || minikube start
  if [[ $(minikube status --format='{{.Host}}') == "Stopped" ]]; then
    echo "Minikube is stopped. Starting minikube!";
    minikube start;
  else
    echo "Minikube is already running!"
  fi
}

function check_k8s_version() {
    current_k8s_version=$(kubectl version --short | grep "Server Version" | awk '{gsub(/v/,$5)}1 {print $3}')
    test_version_comparator 1.20 "$current_k8s_version" '<'
    if [[ $k8s_version == "ok" ]]; then
      echo "current kubernetes version is ok"
    else
      minikube start --kubernetes-version=v1.22.4;
    fi
}

function add_helm_repos() {
  helm repo add argo https://argoproj.github.io/argo-helm;
  helm repo add hashicorp https://helm.releases.hashicorp.com;
  helm repo update argo hashicorp;
}

function install_vault() {
  helm upgrade -i vault hashicorp/vault \
    --atomic \
    --create-namespace -n vault \
    --version=0.18.0 || { echo "Failure of Vault installation. Aborting."; exit 1; }
}

function init_vault() {
  while [[ $(kubectl -n vault get pod vault-0 --no-headers | awk '{print $3}') != 'Running' ]]; do
    kubectl -n vault get pod vault-0 --no-headers; sleep 5;
  done

  if [[ $(kubectl -n vault exec vault-0 -- vault status 2> /dev/null \
  | awk '/Initialized / {print $2}') == "true" ]]; then
    echo "Vault is already Initialized!"
  else
    echo "Vault is not init. Start Initializing...";
    kubectl -n vault exec vault-0 -- vault operator init > vault.log
  fi
}

function unseal_vault() {
  if [[ "$(kubectl -n vault exec vault-0 -- vault status 2>/dev/null | awk '/Sealed / {print $2}')" == "false" ]]; then
    echo "Vault already unsealed!"
  else
    if [[ -f "vault.log" ]]; then
      array_of_vault_keys=()

      echo "Import unseal keys"
      for i in $(seq 1 "$(awk '/Unseal Key/ {print $4}' vault.log | wc -l)"); do
        array_of_vault_keys+=("$(awk "/Unseal Key ${i}:/ {print \$4}" vault.log)")
      done

      echo "Starting unseal..."
      for i in "${array_of_vault_keys[@]}"; do
        if [[ "$(kubectl -n vault exec vault-0 -- vault status 2>/dev/null | awk '/Sealed / {print $2}')" == "true" ]]; then
          kubectl -n vault exec vault-0 -- vault operator unseal "${i}"
        else
          break
        fi
      done

    else
      echo "There is no vault.log file with unseal keys and root token. Aborting."; exit 1;
    fi
  fi
}

function enable_vault_k8s_auth() {

  vault_root_token=$(awk "/Initial Root Token:/ {print \$4}" vault.log)
  kubectl -n vault exec vault-0 -- vault login "${vault_root_token}";

  if [[ $(kubectl -n vault exec vault-0 -- vault auth list | awk '/kubernetes/ {print $1}') == "kubernetes/" ]]; then
    echo "kubernetes auth already enabled!"
  else

    kubectl -n vault exec vault-0 -- vault auth enable kubernetes;
    token_reviewer_jwt=$(kubectl -n vault exec vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    k8s_address=$(kubectl -n vault exec vault-0 -- ash -c 'echo $KUBERNETES_SERVICE_HOST')

    kubectl -n vault exec vault-0 -- vault write auth/kubernetes/config issuer="https://kubernetes.default.svc.cluster.local" \
      token_reviewer_jwt="${token_reviewer_jwt}" \
      kubernetes_host="https://$k8s_address:443" \
      kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  fi
}

function add_vault_permission() {
  kubectl -n vault exec vault-0 -- ash -c 'cat << EOF > /tmp/policy.hcl
path "avp/data/test" { capabilities = ["read"] }
EOF'

  kubectl -n vault exec vault-0 -- vault policy write argocd-repo-server /tmp/policy.hcl

  kubectl -n vault exec vault-0 -- vault write auth/kubernetes/role/argocd-repo-server \
  	bound_service_account_names=argocd-repo-server \
    bound_service_account_namespaces=argocd policies=argocd-repo-server
}

function add_vault_secret() {
  if [[ $(kubectl -n vault exec vault-0 -- vault secrets list | awk '/avp\// {print $1}') == "avp/" ]]; then
    echo "Vault avp secret path already exist"
  else 
    echo "Vault avp secret path already exist"
    kubectl -n vault exec vault-0 -- vault secrets enable -path=avp -version=2 kv
  fi
    kubectl -n vault exec vault-0 -- vault kv put avp/test sample=secret
}

function install_argocd() {
  helm upgrade -i argocd argo/argo-cd \
    --atomic \
    --create-namespace -n argocd \
    -f argocd-values.yaml \
    --version=3.29.5 || { echo "Failure of ArgoCD installation. Aborting."; exit 1; }
}

function check_argocd() {
  # Get ArgoCD admin password
  argocd_admin_password=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

  # Get ArgoCD server pod name
  argoCDServerPod=$(kubectl -n argocd get pod --no-headers | awk '/argocd-server/ {print $1}')

  #  Login via admin in ArgoCD
  kubectl -n argocd exec "${argoCDServerPod}" -- argocd login localhost:8080 --insecure --username=admin --password="${argocd_admin_password}"

  # Check the default project
  defProj=$(kubectl -n argocd exec -ti "${argoCDServerPod}" -- argocd proj get default 2>/dev/null)
  cat << EOF

Get project info
$defProj

EOF

  # Sync main app
  while [[ $(kubectl -n argocd exec "${argoCDServerPod}" -- \
    argocd app sync --force main 2>/dev/null | awk '/ Error/ {print $2}' | tr -d "[:space:]") == 'Error' ]]; do
    echo "Hard refresh of main app...";
    kubectl -n argocd exec "${argoCDServerPod}" -- argocd app terminate-op main 2>/dev/null;
    kubectl -n argocd exec "${argoCDServerPod}" -- argocd app sync --force main 2>/dev/null;
    sleep 10;
  done

  # Sync app-of-secrets
  echo "";
  kubectl -n argocd exec "${argoCDServerPod}" -- argocd app sync --force app-of-secrets 2>/dev/null;
  kubectl -n argocd exec "${argoCDServerPod}" -- argocd app wait app-of-secrets --timeout 180;
}

function test_sample_secret() {
  if [[ $(kubectl -n default get secret example-secret -o jsonpath='{.data}') == '{"sample-secret":"c2VjcmV0"}' ]]; then
    echo ""
    echo "Secret created successfully"
  else
    echo ""
    echo "FAIL. Secret created unsuccessfully"
  fi
}

function go_to_vault_and_argocd() {
    cat << EOF

ArgoCD available in  https://localhost:8080  with:
Login: admin
Password: ${argocd_admin_password}

Vault available in  http://localhost:8081  with:
Token: ${vault_root_token}

EOF

    kubectl port-forward service/argocd-server -n argocd 8080:443 &
    kubectl port-forward service/vault -n vault 8081:8200
}

# the comparator based on https://stackoverflow.com/a/4025065
function version_comparator () {
    if [[ $1 == $2 ]]
    then
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            return 2
        fi
    done
    return 0
}

function test_version_comparator () {
    version_comparator $1 $2
    case $? in
        0) op='=';;
        1) op='>';;
        2) op='<';;
    esac
    if [[ $op != "$3" ]]
    then
        echo "Kubernetes test fail: Expected '$3', Actual '$op', Arg1 '$1', Arg2 '$2'"
        k8s_version="not ok"
    else
        echo "Kubernetes test pass: '$1 $op $2'"
        k8s_version="ok"
    fi
}

function main() {
    check_current_dir
    check_components_install
    check_minikube_is_running
    check_k8s_version
    add_helm_repos
    install_vault
    init_vault
    unseal_vault
    enable_vault_k8s_auth
    add_vault_permission
    add_vault_secret
    install_argocd
    check_argocd
    test_sample_secret
    go_to_vault_and_argocd
}

main
