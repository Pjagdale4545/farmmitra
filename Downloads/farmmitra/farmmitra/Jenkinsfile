pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                // Verbose Git output
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/master']],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [[$class: 'CloneOption', noTags: false, shallow: false, depth: 0, reference: '', timeout: 10, verbose: true]],
                    userRemoteConfigs: [[
                        url: 'https://github.com/Pjagdale4545/farmmitra.git',
                        credentialsId: 'farmmitra2'
                    ]]
                ])
            }
        }


        stage('Build') {
            steps {
                echo 'Building Pharma Mitra project...'
                sh 'mvn clean compile'
            }
        }

       
        stage('Package') {
            steps {
                echo 'Packaging the application...'
                sh 'mvn package'
            }
        }
    }

    post {
        success {
            echo 'Build successful!'
        }
        failure {
            echo 'Build failed!'
        }
    }
}
