package com.example.federationdemo.validation;

public class CredentialKidHolder {
    private static final ThreadLocal<String> HOLDER = new ThreadLocal<>();

    public static void set(String kid) { HOLDER.set(kid); }
    public static String get() { return HOLDER.get(); }
    public static void clear() { HOLDER.remove(); }
}
