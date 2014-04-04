package de.doridian.mcsecuritymanager;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.jar.Attributes;
import java.util.jar.JarFile;

public class SecurityMain {
	public static void main(String[] args) {
		try {
			realMain(args);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	static boolean isInternalPackage(String pkg) {
		return pkg.equals("de.doridian.mcsecuritymanager") || pkg.equals("net.md_5.bungee") || pkg.equals("net.minecraft") || pkg.equals("org.bukkit") || pkg.startsWith("net.minecraft.") || pkg.startsWith("org.bukkit.") || pkg.startsWith("net.md_5.bungee.");
	}

	private static void realMain(final String[] args) throws Exception {
		final File file = new File(System.getProperty("de.doridian.mcsecuritymanager.launchJar"));
		final String mainClass = new JarFile(file).getManifest().getMainAttributes().getValue(Attributes.Name.MAIN_CLASS);

		final MCSecurityClassLoader urlClassLoader = new MCSecurityClassLoader(new URL[] { file.toURI().toURL() });
		final Method m = urlClassLoader.loadClass(mainClass).getMethod("main", String[].class);

		Thread t = new Thread() {
			public void run() {
				try {
					System.setSecurityManager(new MCSecurityManager(urlClassLoader));
					m.invoke(null, new Object[]{args});
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

			@Override
			public void setContextClassLoader(ClassLoader cl) {
				if(!isInternalPackage(cl.getClass().getPackage().getName()))
					throw new RuntimeException("DENIED");
				super.setContextClassLoader(cl);
			}
		};
		t.setContextClassLoader(urlClassLoader);
		t.start();
	}
}
