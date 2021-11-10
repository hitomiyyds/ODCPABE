package com.example.authority;

/**
 * 机构密钥（authorityID，publicKey，secretKey）
 * @author user01
 */
public class AuthorityKey {
    private static final long serialVersionUID = 1235123412341245L;
    private String authorityID;
    private AuthPublicKey publicKey;
    private AuthSecretKey secretKey;


    public AuthorityKey(String authorityID, AuthPublicKey Apk, AuthSecretKey Ask) {
        this.authorityID = authorityID;
        publicKey = Apk;
        secretKey = Ask;
    }



    public String getAuthorityID() {
        return authorityID;
    }

    public AuthPublicKey getPublicKey() {
        return publicKey;
    }

    public AuthSecretKey getSecretKey() {
        return secretKey;
    }

    @Override
    public String toString() {
        return "AuthorityKey{" +
                "authorityID='" + authorityID + '\'' +
                ", \t\npublicKey=" + publicKey +
                ", \t\nsecretKey=" + secretKey +
                '}';
    }
}
