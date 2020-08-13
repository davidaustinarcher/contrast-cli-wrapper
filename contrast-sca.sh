#!/bin/bash

normal=$(tput sgr0)
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)

cli_api_key=${cli_api_key:-}
cli_authorization=${cli_authorization:-}
cli_organization_id=${cli_organization_id:-}
cli_host=${cli_host:-}
cli_application_name=${cli_application_name:-}
cli_language=${cli_language:-}
cli_project_path=${cli_project_path:-./}
cli_application_id=${cli_application_id:-}

while [ $# -gt 0 ]; do

   if [[ $1 == *"--"* ]]; then
        param="${1/--/}"
        declare $param="$2"
   fi

  shift
done

if [[ $cli_application_id == "" ]]
then
    #Try to create the application
    result=$(contrast-cli --cli_api_key $cli_api_key \
    --cli_authorization $cli_authorization \
    --cli_organization_id $cli_organization_id \
    --cli_host $cli_host \
    --cli_application_name $cli_application_name \
    --cli_language $cli_language \
    --cli_project_path $cli_project_path \
    --cli_catalogue_application)

    #If the app was created, grab the Id
    if [[ ${result} =~ "SUCCESS" ]]
    then
        echo "Application $cli_application_name created"
        APP_ID=${result:138:36}
    else
        if [[ ${result} =~ "Application already exists" ]]
        then
            #App already exists
            echo "Application $cli_application_name already exists"
            APP_ID=${result:(-36)}
        else
            #Something else, bail out
            printf "${red}Unexpected response: $result${normal}\n"
            exit
        fi 
    fi 

    echo "The Application Id for $cli_application_name is $APP_ID"
else
    APP_ID=$cli_application_id
fi

#Upload the libraries
echo "Running Contrast CLI tool"
result=$(contrast-cli --cli_api_key $cli_api_key \
--cli_authorization $cli_authorization \
--cli_organization_id $cli_organization_id \
--cli_host $cli_host \
--cli_project_path $cli_project_path \
--cli_application_id $APP_ID)

if [[ ${result} =~ "SUCCESS" ]]
then
    echo "Libraries uploaded for application id: $APP_ID"
else
    printf "${red}Unexpected response: $result${normal}\n"
    exit
fi

#Fetch the list of libraries 
echo "Fetching libraries from the Contrast API"


URL=https://$cli_host/Contrast/api/ng/sca/organizations/$cli_organization_id/applications/$APP_ID/reports
result=$(curl --silent --location --request GET $URL \
--header "API-Key: $cli_api_key" \
--header "Accept: application/json" \
--header "Authorization: $cli_authorization")

echo "Preparing request"
LANG=$(echo "$cli_language" | tr "[A-Z]" "[a-z]")
payload=$(echo $result | jq ".reports[0].report.$LANG.dependencyTree | keys[] as \$k | (.[\$k][]) | {name: .name, group: .group, version: .resolved}" | jq --slurp "{\"name_group_versions\": ., \"language\": \"$cli_language\"}")

echo "Fetching vulnerabilities"
libs=$(curl --silent --location --request PUT "https://$cli_host/Contrast/api/ng/$cli_organization_id/libraries/artifactsByGroupNameVersion" \
--header "API-Key: $cli_api_key" \
--header "Accept: application/json" \
--header 'Content-Type: application/json' \
--header "Authorization: $cli_authorization" \
--data-raw "$payload")

echo $payload > payload.json
echo $libs > libs.json

#Remove some invalid chars from json
libs=$(echo $libs| sed 's/\\\\//g') #\\
libs=$(echo $libs| sed 's/\\"//g') #\"

#Count the libs
count=$(echo $libs | jq '.libraries | length')

#Select and count the vulnerable libraries
vulnerable_libraries=$(echo $libs | jq '.libraries[] | select( .vulns | length > 0)')
vuln_count=$(echo $vulnerable_libraries | jq -s 'length')

if [[ $vuln_count == 0 ]]
then
    printf "${green}Hooray! No vulnerable libraries were detected in out of ${normal}$count${green} libraries analysed${normal}\n"
else
    #Flatten the json
    data=$(echo $vulnerable_libraries | jq '. as $lib | .vulns[] | {hash: $lib.hash, library:$lib.file_name, group: $lib.group, version: $lib.file_version, CVE: .name, description: .description, severity_code: .severity_code, severity_value: .severity_value}')

    #Sort by name then severity
    data=$(echo $data | jq --slurp '. | sort_by(.group, .file_name, -.severity_value)')

    #Count the number of CVEs
    cve_count=$(echo $data | jq '. | length')

    echo $data | jq -c '.[]' | while IFS='' read vuln;do
        hash=$(echo "$vuln" | jq -r .hash)
        name=$(echo "$vuln" | jq -r .library)
        group=$(echo "$vuln" | jq -r .group)
        version=$(echo "$vuln" | jq -r .version)
        cve=$(echo "$vuln" | jq -r .CVE)
        severity_code=$(echo "$vuln" | jq -r .severity_code)
        severity_value=$(echo "$vuln" | jq -r .severity_value)
        description=$(echo "$vuln" | jq -r .description)

        if [[ $hash != $previous ]]
        then
            printf "${blue}$group/$name ($version) is vulnerable:${normal}\n"
            previous=$hash
        fi

        if [[ $severity_code == "HIGH" ]]
        then
            printf "${red}$severity_code ($severity_value)${normal}"    
        else 
            if [[ $severity_code == "MEDIUM" ]]
            then
                printf "${yellow}$severity_code ($severity_value)${normal}"    
            else 
                printf "$severity_code ($severity_value)"
            fi
        fi
        echo -e " $cve: $description\n" | fmt -w 200
    done

    printf "${green}Found ${normal}$cve_count${green} CVEs within ${normal}$vuln_count${green} vulnerable libraries${normal}\n"
fi
printf "You can view the hierarchy tree here: https://$cli_host/Contrast/static/ng/index.html#/$cli_organization_id/applications/$APP_ID/libs/dependency-tree\n"