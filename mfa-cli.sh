#!/bin/bash

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case ${1} in
    --profile)
      AWS_PROFILE="--profile ${2}"
      shift # past argument
      shift # past value
      ;;
    --region)
      AWS_CLI_REGION="${2}"
      shift # past argument
      shift # past value
      ;;
    --duration-seconds)
      SESSION_DURATION_SECONDS=${2}
      shift # past argument
      shift # past value
      ;;
    --mfa-serial)
      MFA_SERIAL_ARN=${2}
      shift # past argument
      shift # past value
      ;;
    --mfa-token)
      MFA_TOKEN=${2}
      shift # past argument
      shift # past value
      ;;
    --create-profile)
      SESSION_PROFILE_NAME=${2}
      shift # past argument
      shift # past value
      ;;
    --create-env)
      CREATE_ENV=y
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option: ${1}"
      return 1
      ;;
    *)
      POSITIONAL_ARGS+=("${1}") # save positional arg
      shift # past argument
      ;;
  esac
done

print_help() {
  [[ -n ${1} ]] && echo "Error: ${1} is required"

  echo """Usage: source ${0} --mfa-serial arn:aws:iam::xxxxxxxxxxx:mfa/xxxxxxx --mfa-token xxxxx --create-env

  Arguments:
  --mfa-serial:       ARN of MFA associated with your IAM user
  --mfa-token:        Secret code generated by your MFA device
  --profile:          (Optional) Use custom aws cli profile to authenticate with sts for generating session credentials
  --region:           (Optional) This region will be used for making sts call and will be set as default region for session credentials
  --duration-seconds: (Optional) Number of seconds for which session credentials will be valid. Default session duration is set to 900 seconds
  --create-profile:   (Optional) Store session credentials as a cli profile. Either --create-profile or --create-env is required
  --create-env:       (Optional) Store session credentials as environment variables. Either --create-profile or --create-env is required
  """
}

[[ -z ${MFA_SERIAL_ARN} ]] && print_help "--mfa-serial" && return 1
[[ -z ${MFA_TOKEN} ]] && print_help "--mfa-token" && return 1
[[ -z ${SESSION_PROFILE_NAME} && -z ${CREATE_ENV} ]] && print_help "--create-profile or --create-env" && return 1
[[ -n ${SESSION_PROFILE_NAME} && -n ${CREATE_ENV} ]] && print_help "Only one of --create-profile or --create-env" && return 1

[[ -z ${SESSION_DURATION_SECONDS} ]] && SESSION_DURATION_SECONDS=900
[[ -z ${AWS_CLI_REGION} ]] && AWS_CLI_REGION=$(aws configure get region $(echo ${AWS_PROFILE}))
[[ -z ${AWS_CLI_REGION} ]] && AWS_CLI_REGION="us-east-1"

echo -n "Fetching session credentials... "
SESSION_CREDENTIALS=$(aws sts get-session-token --duration-seconds ${SESSION_DURATION_SECONDS} --serial-number ${MFA_SERIAL_ARN} --token-code ${MFA_TOKEN} $(echo ${AWS_PROFILE}) $(echo "--region ${AWS_CLI_REGION}"))
[[ $? -gt 0 ]] && return 1
echo "ok"

if [[ -n ${CREATE_ENV} ]]; then
  export AWS_ACCESS_KEY_ID=$(echo "${SESSION_CREDENTIALS}" | jq -r '.Credentials.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo "${SESSION_CREDENTIALS}" | jq -r '.Credentials.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo "${SESSION_CREDENTIALS}" | jq -r '.Credentials.SessionToken')
  export AWS_REGION=${AWS_CLI_REGION}
elif [[ -n ${SESSION_PROFILE_NAME} ]]; then
  aws configure set aws_access_key_id $(echo "${SESSION_CREDENTIALS}" | jq -r '.Credentials.AccessKeyId') --profile ${SESSION_PROFILE_NAME}
  aws configure set aws_secret_access_key $(echo "${SESSION_CREDENTIALS}" | jq -r '.Credentials.SecretAccessKey') --profile ${SESSION_PROFILE_NAME}
  aws configure set aws_session_token $(echo "${SESSION_CREDENTIALS}" | jq -r '.Credentials.SessionToken') --profile ${SESSION_PROFILE_NAME}
  aws configure set region ${AWS_CLI_REGION} --profile ${SESSION_PROFILE_NAME}
fi

unset MFA_SERIAL_ARN MFA_TOKEN SESSION_PROFILE_NAME CREATE_ENV SESSION_DURATION_SECONDS AWS_CLI_REGION SESSION_CREDENTIALS AWS_PROFILE
echo "Session credentials generated successfuly"
