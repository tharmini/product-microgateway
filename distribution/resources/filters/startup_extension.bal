import ballerinax/java;

public function startupExtension() {
    loadDataToMemory();
}

function LoadDataToMemory() = @java:Method {
    name: "readDataToMemory",
    class: "org.wso2.apimgt.gateway.cli.utils.storeDetails"
}

