
#!/bin/bash
# generate test purpose certificates for pipefitter communication

# this also works for MAC. For linux we can use "readlink -f"
realpath() {
      [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}
SCRIPT_PATH=`realpath "$0"`
SCRIPT_DIR=`dirname $SCRIPT_PATH`
PROJ_DIR=$SCRIPT_DIR/../
KUBECTL=$PROJ_DIR/_output/bin/kubectl

mkdir -p $PROJ_DIR/certs/

# find CA key. For lazy reason, we directly use docker-machine. In fact, keys should be distributed in
# a more robust way...
docker-machine ssh master "sudo cat /etc/kubernetes/pki/ca.key" > ca.key;
chmod 600 ca.key
docker-machine ssh master "sudo cat /etc/kubernetes/pki/ca.crt" > ca.crt;
docker-machine ssh master "cat .kube/config" > admin-config;
chmod 600 admin-config;
master_ip=`docker-machine ip master`
sed -i 's/server: https:.*/server: https:\/\/'$master_ip':6443/' admin-config;

gen_key() {
openssl ecparam -name prime256v1 -out $1_param.pem 
openssl ecparam -name prime256v1 -in $1_param.pem -genkey -noout -out $1_ec.key
# convert the EC key to PKCS key
openssl pkcs8 -topk8 -nocrypt -in $1_ec.key -outform PEM -out $1.key
rm -f $1_param.pem $1_ec.key tmp-$1.key
}

# TODO: configs may be merged into a common CA config file, so the shell cmd could look elegant.
gen_cert() {
openssl req -new -key $1.key -out $1.csr -subj "/O=users/CN=$1" #-config $SCRIPT_DIR/openssl.cnf 
openssl x509 -req -days 1000 -in $1.csr -CA $2.crt -CAkey $2.key -set_serial 0101 -out $1.crt -sha256 -extensions 'v3_req' #-extfile $SCRIPT_DIR/openssl.cnf 
}

wrap_config() {
  local master_ip=`docker-machine ip master`
  sed 's/USERNAME/'$1'/' config-template > config-$1
  $KUBECTL config --kubeconfig=config-$1 set-cluster kubernetes --server=https://$master_ip:6443 --certificate-authority=ca.crt --embed-certs=true
  $KUBECTL config --kubeconfig=config-$1 set-credentials $1 --client-certificate=$1.crt --client-key=$1.key --embed-certs=true
  $KUBECTL config --kubeconfig=config-$1 set-context latte --cluster=kubernetes --namespace=latte-$1 --user=$1
  $KUBECTL config --kubeconfig=config-$1 use-context latte
  $KUBECTL config --kubeconfig=config-$1 view
}

gen_role_and_privilege() {
  sed 's/USERNAME/'$1'/' userrole.yml > role-$1.yml
  $KUBECTL --insecure-skip-tls-verify=true --kubeconfig=admin-config create namespace latte-$1
  $KUBECTL --insecure-skip-tls-verify=true --kubeconfig=admin-config delete -f role-$1.yml
  $KUBECTL --insecure-skip-tls-verify=true --kubeconfig=admin-config create -f role-$1.yml
}

gen_key kuser1
gen_cert kuser1 ca
wrap_config kuser1
gen_role_and_privilege kuser1
gen_key kuser2
gen_cert kuser2 ca
wrap_config kuser2
gen_role_and_privilege kuser2

