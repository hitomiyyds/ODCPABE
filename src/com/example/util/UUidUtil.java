package com.example.util;

import java.security.MessageDigest;
import java.util.Random;
import java.util.UUID;
import org.apache.commons.codec.binary.Hex;
public class UUidUtil {
    public static String getUUid() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    /**
     * 生成含有随机盐的密码
     */
    public static String generate(String password) {
        int i1 = new Random().nextInt(99999999);
        int i2 = new Random().nextInt(99999999);
        String salt = String.valueOf(i1) + String.valueOf(i2);
        if (salt.length() < 16) {
            for (int i = 0; i < 16 - salt.length(); i++) {
                salt += "0";
            }
        }
        password = md5Hex(password + salt);
        char[] cs1 = password.toCharArray();
        char[] cs2 = salt.toCharArray();
        char[] cs = new char[48];
        for (int i = 0; i < 48; i += 3) {
            cs[i] = cs1[i / 3 * 2];
            cs[i + 1] = cs2[i / 3];
            cs[i + 2] = cs1[i / 3 * 2 + 1];
        }
        return new String(cs);
    }

    /**
     * 校验密码是否正确
     */
    public static boolean verify(String password, String md5) {
        char[] cs = md5.toCharArray();
        char[] cs1 = new char[32];
        char[] cs2 = new char[16];
        for (int i = 0; i < 48; i += 3) {
            cs1[i / 3 * 2] = cs[i];
            cs1[i / 3 * 2 + 1] = cs[i + 2];
            cs2[i / 3] = cs[i + 1];
        }
        String salt = new String(cs2);
        return md5Hex(password + salt).equals(new String(cs1));
    }

    /**
     * 获取十六进制字符串形式的MD5摘要
     */
    private static String md5Hex(String src) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] bs = md5.digest(src.getBytes());
            return new String(new Hex().encode(bs));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String[] args) {
        String password = generate("admin");
        System.out.println(verify("admin", password));
    }
}
