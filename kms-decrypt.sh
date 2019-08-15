#!/bin/bash
# Decrypt the specified cipher text string using AWS KMS
# Must have the awscli command line tools installed
# The AWS credentials in the specified credentials profile
# must have IAM permissions to decrypt using the same KMS encryption
# key that was used to encrypt and generate the specified cipher text.

profile="default"
encryption_context=""

while [ "$1" != "" ]; do
    case $1 in
        -c | --cipher )         shift
                                cipher=$1
                                ;;
        -p | --profile )        shift
                                profile=$1
                                ;;
        -e | --enc-context )    shift
                                encryption_context=$1
                                ;;
        -r | --region )         shift
                                region=$1
                                ;;
    esac
    shift
done

context_args=""
if [ "$encryption_context" != "" ]; then
    context_args="--encryption-context Key=$encryption_context"
else
    echo "no encryption context"
fi

echo "cipher $cipher"
echo "region $region"
echo "profile $profile"
echo "enc-context $encryption_context"
echo "context_args $context_args"

aws kms decrypt --profile $profile --region $region --ciphertext-blob fileb://<(echo "$cipher" | base64 -D) $context_args --output text --query Plaintext | base64 -D
echo ""
