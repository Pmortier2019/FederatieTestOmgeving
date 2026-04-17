package com.example.federationdemo.validation;

import java.util.List;

public class CredentialTrustChainHolder {
    private static final ThreadLocal<List<String>> HOLDER = new ThreadLocal<>();

    public static void set(List<String> chain) { HOLDER.set(chain); }
    public static List<String> get() { return HOLDER.get(); }
    public static void clear() { HOLDER.remove(); }
}
