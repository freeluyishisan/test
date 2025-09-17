import java.lang.instrument.Instrumentation;

public class SafeAgent {
    // JVM 启动时加载
    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[SafeAgent] premain loaded with args: " + agentArgs);
        // 可以做一些安全实验，例如列出已加载类
        for (Class<?> cls : inst.getAllLoadedClasses()) {
            System.out.println("[SafeAgent] Loaded class: " + cls.getName());
        }
    }

    // JVM 已经运行后动态加载
    public static void agentmain(String agentArgs, Instrumentation inst) {
        System.out.println("[SafeAgent] agentmain loaded with args: " + agentArgs);
        // 做一些安全实验，例如打印 JVM 系统属性
        System.getProperties().forEach((k, v) -> System.out.println("[SafeAgent] " + k + " = " + v));
    }
}
