package org.wso2.micro.gateway.core.mutualssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.micro.gateway.core.Constants;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public  class MutualsslRequestInvoker {
    private String trustStorePath;
    private String trustStorePassword;
    public static FileInputStream localTrustStoreStream;

    private static final Logger log = LoggerFactory.getLogger("ballerina");

    public static boolean invokegetcert(String certB64, String trustStorePath, String trustStorePassword) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        byte[] decoded = Base64.getDecoder().decode(certB64);

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decoded));
        localTrustStoreStream = new FileInputStream(getKeyStorePath(trustStorePath));
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(localTrustStoreStream, trustStorePassword.toCharArray());
        String certificateAlias = trustStore.getCertificateAlias(cert);
        boolean isexist = isCertificateExistsInTrustStore(cert,trustStore);

        return isexist;
    }


    public  static boolean isCertificateExistsInTrustStore(X509Certificate certificate,KeyStore trustStore ) {

        if (certificate != null) {
            try {

                if (trustStore != null) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    byte[] certificateEncoded = certificate.getEncoded();
                    try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certificateEncoded)) {
                        java.security.cert.X509Certificate x509Certificate =
                                (java.security.cert.X509Certificate) cf.generateCertificate(byteArrayInputStream);
                        String certificateAlias = trustStore.getCertificateAlias(x509Certificate);
                        if (certificateAlias != null) {
                            return true;
                        }
                    }
                }
            } catch (KeyStoreException | CertificateException  | IOException e) {
                String msg = "Error in validating certificate existence";
                log.error(msg, e);

            }
        }
        return false;
    }

    public static BigInteger getSerialNumberOfCert(String cert) throws CertificateException {
        byte[] decoded = Base64.getDecoder().decode(cert);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decoded));

        BigInteger serial_number = certificate.getSerialNumber();
        return serial_number;

    }

    /**
     * Used to get the keystore path
     */
    public static String getKeyStorePath(String fullPath) {
        String homePathConst = "\\$\\{mgw-runtime.home}";
        String homePath = System.getProperty(Constants.RUNTIME_HOME_PATH);
        return fullPath.replaceAll(homePathConst, homePath);
    }



}
