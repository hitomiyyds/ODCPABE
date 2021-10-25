package authority;

import java.util.Arrays;

/**
 * @author user01
 * 具体机构私钥
 */
public class AuthSecretKey {
    private static final long serialVersionUID = 1L;
    private byte[] ai;
    private byte[] yi;

    public AuthSecretKey(byte[] ai, byte[] yi) {
        this.ai = ai;
        this.yi = yi;
    }

    public byte[] getAi() {
        return ai;
    }

    public byte[] getYi() {
        return yi;
    }

    @Override
    public String toString() {
        return "AuthSecretKey{" +
                "ai=" + Arrays.toString(ai) +
                ", yi=" + Arrays.toString(yi) +
                '}';
    }
}
