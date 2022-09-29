package org.jarEncoder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
 
// 加密jar代码
public class JarEncryptor {
 
    public static void encrypt(String fileName, String dstName) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            File srcFile = new File(fileName);
            File dstFile = new File(dstName);
            FileOutputStream dstFos = new FileOutputStream(dstFile);
            JarOutputStream dstJar = new JarOutputStream(dstFos);
            JarFile srcJar = new JarFile(srcFile);
            for (Enumeration<JarEntry> enumeration = srcJar.entries(); enumeration.hasMoreElements(); ) {
                JarEntry entry = enumeration.nextElement();
                InputStream is = srcJar.getInputStream(entry);
                int len;
                while ((len = is.read(buf, 0, buf.length)) != -1) {
                    bos.write(buf, 0, len);
                }
                byte[] bytes = bos.toByteArray();
                String name = entry.getName();
                if (name.startsWith("javaTest") && name.endsWith(".class")) {
					System.out.println("Encoder Class Name:"+name);
                    try {
						System.out.println("bytesLen:"+bytes.length);
                        bytes = ByteCodeEncryptor.encrypt(bytes);
						System.out.println("After bytesLen:"+bytes.length);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                JarEntry ne = new JarEntry(name);
                dstJar.putNextEntry(ne);
                dstJar.write(bytes);
                bos.reset();
            }
            srcJar.close();
            dstJar.close();
            dstFos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 
    public static void main(String[] args) {
        if (args == null || args.length == 0) {
            System.out.println("please input parameter");
            return;
        }
        if (args[0].endsWith(".jar")) {
            JarEncryptor.encrypt(args[0], args[0].substring(0, args[0].lastIndexOf(".")) + "_encrypted.jar");
        } else {
            System.out.println("Please input your Jar file.");
        }
    }
 
}