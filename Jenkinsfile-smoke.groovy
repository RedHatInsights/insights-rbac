/*
* Requires: https://github.com/RedHatInsights/insights-pipeline-lib
*/

@Library("github.com/RedHatInsights/insights-pipeline-lib") _

if (env.CHANGE_ID) {
    runSmokeTest (
        ocDeployerBuilderPath: "rbac/rbac",
        ocDeployerComponentPath: "rbac/rbac",
        ocDeployerServiceSets: "rbac",
        iqePlugins: ["iqe-rbac-plugin"],
        pytestMarker: "smoke",
    )
}