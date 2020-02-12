/*
* Requires: https://github.com/RedHatInsights/insights-pipeline-lib
*/

@Library("github.com/RedHatInsights/insights-pipeline-lib@v3") _

if (env.CHANGE_ID) {
    execSmokeTest (
        ocDeployerBuilderPath: "rbac/rbac",
        ocDeployerComponentPath: "rbac/rbac",
        ocDeployerServiceSets: "rbac",
        iqePlugins: ["iqe-rbac-plugin"],
        pytestMarker: "rbac_smoke",
        configFileCredentialsId: "settings_rbac_smoke"
    )
}
