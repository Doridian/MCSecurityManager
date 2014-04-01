package de.doridian.mcsecuritymanager;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
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

	private static void realMain(final String[] args) throws Exception {
		final File file = new File(System.getProperty("de.doridian.mcsecuritymanager.launchJar"));
		final String mainClass = new JarFile(file).getManifest().getMainAttributes().getValue(Attributes.Name.MAIN_CLASS);

		final URLClassLoader urlClassLoader = new URLClassLoader(new URL[] { file.toURI().toURL() });
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
		};
		t.setContextClassLoader(urlClassLoader);
		t.start();
	}
}
