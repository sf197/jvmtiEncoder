package org.jarEncoder;

import java.io.File;

public class ByteCodeEncryptor {
 
    static {
        String realPath = System.getProperty("user.dir") + File.separator +"JarEncoder.so" ;
		System.load(realPath);
    }
 
    public native static byte[] encrypt(byte[] text);
 
}