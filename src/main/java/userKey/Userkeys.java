package userKey;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 用户密钥
 * 用户ID
 * 用户与用户
 *
 * @author user01
 */
public class Userkeys {
    private static final long serialVersionUID = 1L;
    private String userID;
    /**
     * 这里的String类型代表的是机构id--aid
     */
    private Map<String, UserAuthorityKey> userAuthKeys;
    private Set<String> attributes;
    private byte[] uUid;
    private byte[] rj;
    private byte[] pj;

    public Userkeys(String UserId) {
        this.userID = UserId;
        this.userAuthKeys = new HashMap<>();
        this.attributes = new HashSet<>();
    }

    public void addKey(UserAuthorityKey ak) {
        userAuthKeys.put(ak.getAuthority(), ak);
    }

    public Set<String> getAuthorities() {
        return userAuthKeys.keySet();
    }

    public String getUserID() {
        return userID;
    }

    public Map<String, UserAuthorityKey> getUserAuthKeys() {
        return userAuthKeys;
    }

    public void addAttributes(Set<String> authAttributes) {
        this.attributes.addAll(authAttributes);
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Set<String> attributes) {
        this.attributes = attributes;
    }

    public byte[] getuUid() {
        return uUid;
    }

    public void setuUid(byte[] uUid) {
        this.uUid = uUid;
    }

    public byte[] getRj() {
        return rj;
    }

    public void setRj(byte[] rj) {
        this.rj = rj;
    }

    public byte[] getPj() {
        return pj;
    }

    public void setPj(byte[] pj) {
        this.pj = pj;
    }

}
