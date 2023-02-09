# Identify issues in your code with CodeThreat

<img src="https://codethreat.com/images/Codethreat-Logo-kucuk-logo-p-500.png">

[CodeThreat](https://codethreat.com) SAST solution has seamless integration with the Jenkins. While it's fairly easy to start security scans and working on the issues found on your code, this document provides details of the integration. 

With CodeThreat custom rule engine, we have wide language and framework support without sacrificing quality.

## Requirements

* A [CodeThreat](https://codethreat.com) account. Contact info@codethreat.com if you don't have one yet.
* Aaand that's all! Now you are ready to jump!

## Usage

An example script for Jenkins Pipeline Item should be as follows.

```script

pipeline {
    agent any
    stages {
        stage("Clone") {
            steps {
               git url: 'https://github.com/<exampleUser>/<exampleRepo>', branch: 'main' //example file
               sh 'zip -r example.zip .'
            }
        }
        stage("Scan") {
            steps {
                withCredentials([usernamePassword(credentialsId: 'codethreat_credentials', usernameVariable: 'username', passwordVariable: 'password')]) {
                    CodeThreatScan(
                        ctServer: env.ctServer_URL,
                        fileName:"webg.zip",
                        max_number_of_high: 23,
                        max_number_of_critical: 23,
                        weakness_is: ".*injection,buffer.over.read,mass.assigment", 
                        condition: "OR",
                        project_name: "exampleProjectName"
                   )
                }
            }
        }
    }
}

```
* The credentials ID should be "codethreat_credentials".

* In `env` section, you can use either the USERNAME,PASSWORD pair as one of the authentication method.

* If more args are provided, they will be `AND`ed together.

* `weakness_is` fields expects either a wildcard or a direct weakness id. Please checkout KStore section of  [CodeThreat](https://codethreat.com) portal application.

## Args

| Variable  | Example Value &nbsp;| Description &nbsp; | Type | Required | Default |
| ------------- | ------------- | ------------- |------------- | ------------- | ------------- |
| max_number_of_critical | 23 | Failed condition for maximum critical number of found issues | Number | No | N/A
| max_number_of_high | 23 | Failed condition for maximum high number of found issues | Number | No | N/A
| weakness_is | ".*injection,buffer.over.read,mass.assigment" | Failed condition for found issues weakness id's. | String | No | N/A
| condition | "OR" | It checks failed arguments(max_number_of_critical, max_number_of_high)  using with "and" or "or". | String | No | AND


## Credentials


- `USERNAME` –  Your CodeThreat Account's username.

- `PASSWORD` – Your CodeThreat Account's passowrd.



