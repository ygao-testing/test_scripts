pipeline {
    agent { label 'docker_agent' }
    stages {
        // Debug stage to confirm the Jenkinsfile and branch
        stage('Jenkinsfile Debug Info') {
            steps {
                script {
                    echo "Running Jenkinsfile from BRANCH: ${BRANCH}"
                }
            }
        }

        stage('Set Parameters') {
            steps {
                script {
                    env.SELENOID_AGENT_IP = "10.65.28.73"
                    echo "Selenoid Agent IP is '${env.SELENOID_AGENT_IP}'"
                }
            }
        }

        stage('Prepare environment') {
            steps{
                cleanWs()
                sh """
                    python3.12 -m venv ./venv
                    . ./venv/bin/activate
                    python -m pip install --upgrade pip
                    git clone git@github.com:lacework-dev/fortiqa.git
                    cd ${WORKSPACE}
                    cd fortiqa
                    git checkout ${BRANCH}
                    python -m pip install -r pytest/fortiqa/tests/requirements.txt
                    pip install pytest-testcenter
                """
            }
        }

        stage('Run GUI tests') {
            environment {
                TESTCENTER_TOKEN = credentials('testcenter_lacework_fcsqa_token')
                aws = credentials('886436945382')
                lw_secret = credentials("fcsqagen2_yahoo_system_e2e_api_key_and_access")
                email_creds = credentials("fcsqagen2_yahoo_app_cred")
            }
            steps {
                script {
                    // Write configuration file inside script block
                    writeFile file: 'fortiqa/pytest/fortiqa/tests/user_config.yaml', text: """
---
app:
    workspace_id: "lacework_gui_test"
    customer:
        lw_api_key: "$lw_secret_USR"
        lw_secret: "$lw_secret_PSW"
        account_name: "fortiqa"
        user_email: "$email_creds_USR"
        user_email_password: "$email_creds_PSW"
        sub_account: ""
    aws_account:
        aws_account_id: "886436945382"
        aws_access_key_id: "$AWS_ACCESS_KEY_ID"
        aws_secret_access_key: "$AWS_SECRET_ACCESS_KEY"
"""
                    def prefix = "./pytest/fortiqa/tests/ui/tests/"
                    if (TEST_PATH == '') {
                        // Get all checkbox values with test area locations from Jenkins Job
                        def folders = TEST_FOLDERS.split(',')
                        // Create a list of transformed paths
                        def transformedPaths = folders.collect { folder -> "${prefix}${folder}" }
                        TEST_PATH = transformedPaths.join(' ')
                    } else {
                        TEST_PATH = "${prefix}${TEST_PATH}"
                    }

                    def videoUrl = "http://${SELENOID_AGENT_IP}:8080/video/${JOB_NAME[13..-1]}_${BUILD_NUMBER}.mp4"
                    def testcenterNotes = "{" +
                            "\"Target URL\": \"${env.TARGET_URL}\", " +
                            "\"Jenkins URL\": \"${env.RUN_TESTS_DISPLAY_URL}\", " +
                            "\"Video\": \"${videoUrl}\"" +
                            "}"
                    sh """
                        cd ${WORKSPACE}
                        . ./venv/bin/activate
                        cd fortiqa
                        git checkout ${BRANCH}
                        pytest ${TEST_PATH} ${FLAGS} --collect-only -q
                        pytest ${TEST_PATH} ${FLAGS} -s -vv --durations=0 --html=report.html --self-contained-html --junitxml=results.xml --tc_dest remote --testcenter_notes '${testcenterNotes}'
                    """
                }
            }
        }
    }
    post {
        always {
            script{
                // Archive the test results
                archiveArtifacts artifacts: '**/report.html,**/results.xml'
                // Publish JUnit test results in Jenkins
                junit '**/results.xml'
            }
        }
    }
}
