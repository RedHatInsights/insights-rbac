/*
* Requires: https://github.com/RedHatInsights/insights-pipeline-lib
*/

@Library("github.com/RedHatInsights/insights-pipeline-lib@v3") _

def options = [vaultEnabled: true, settingsFromGit: true]

if (env.CHANGE_ID) {
    execSmokeTest (
        ocDeployerBuilderPath: "rbac/rbac",
        ocDeployerComponentPath: "rbac/rbac",
        ocDeployerServiceSets: "rbac",
        iqePlugins: ["iqe-rbac-plugin"],
        pytestMarker: "rbac_smoke",
        appConfigs: [rbac: [plugins: ["rbac"]]]
    )
}
