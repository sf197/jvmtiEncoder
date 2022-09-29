# Java Jar包加密/解密工具

编译动态链接库

```bash
JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64/"
g++ -fPIC -shared -g -o JarEncoder.so -I$JAVA_HOME/include  -I$JAVA_HOME/include/linux/ JarEncoder.cpp
```



加密Bird.jar包

```bash
javac -d . org/jarEncoder/JarEncryptor.java
java org.jarEncoder.JarEncryptor Bird.jar
```



运行时解密

```bash
java -agentpath:./JarEncoder.so -jar Bird_encrypted.jar
```

