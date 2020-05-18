package org.wso2.apimgt.gateway.cli.model.config;

public class MutualSslCertificate {

    private boolean mandatory = false;

    private String certificateInformation = null;

    public boolean isMandatory() {
        return mandatory;

    }
    public void setMandatory(boolean mandatory) {
        this.mandatory = mandatory;
    }
    public String getCertificateInformation() {
        System.out.println("certificateInformation*" + certificateInformation);
        return certificateInformation;
    }
    public void setCertificateInformation(String certificateInformation) {
        this.certificateInformation = certificateInformation;
    }
}
