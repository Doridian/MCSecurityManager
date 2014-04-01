package de.doridian.mcsecuritymanager;

import java.io.File;
import java.io.IOException;
import java.security.Permission;
import java.util.*;

public class MCSecurityManager extends SecurityManager {
	private final Set<ClassLoader> systemClassLoader = Collections.newSetFromMap(new IdentityHashMap<ClassLoader, Boolean>());
	private final ClassLoader ownClassLoader;

	private final String proxyHost;
	private final int proxyPort;

	private final Set<File> allowedPaths = new HashSet<File>();

	MCSecurityManager(ClassLoader protectedClassLoader) {
		this.systemClassLoader.add(this.getClass().getClassLoader());
		this.systemClassLoader.add(ClassLoader.getSystemClassLoader());
		ownClassLoader = protectedClassLoader;

		int pport = -1;
		try {
			pport = Integer.parseInt(System.getProperty("http.proxyPort"));
		} catch (Exception e) { }
		proxyHost = System.getProperty("http.proxyHost");
		proxyPort = pport;

		addCanonicalAllowedFile(System.getProperty("user.dir"));
		addCanonicalAllowedFile(System.getProperty("java.io.tmpdir"));
		addCanonicalAllowedFile(System.getProperty("java.home"));
		addCanonicalAllowedFile("/dev/random");
		addCanonicalAllowedFile("/dev/urandom");
	}

	private void addCanonicalAllowedFile(String file) {
		try {
			allowedPaths.add(new File(file).getCanonicalFile());
		} catch (IOException e) { }
	}

	private Class getFirstUserspaceClass() {
		Class[] classes = getClassContext();
		for(int i = 1; i < classes.length; i++) {
			Class clazz = classes[i];
			ClassLoader classLoader = clazz.getClassLoader();
			if(classLoader != null && !systemClassLoader.contains(classLoader))
				return clazz;
		}
		return null;
	}

	private boolean isMainUserspaceComponent() {
		Class userspaceClass = getFirstUserspaceClass();
		return userspaceClass != null && userspaceClass.getClassLoader() == ownClassLoader;
	}

	private boolean isUserspaceComponent() {
		return getFirstUserspaceClass() != null;
	}

	@Override
	public void checkConnect(String host, int port) {
		if(port == -1) {
			informAboutAction("resolved \"" + host + "\"", false);
		} else {
			if(port == proxyPort && host.equals(proxyHost))
				return;
			informAboutAction("connected to \"" + host + "\" on port " + port, false);
		}
	}

	@Override
	public void checkConnect(String host, int port, Object context) {
		checkConnect(host, port);
	}

	private void informAboutAction(String action, boolean deny) {
		Class userspaceClass = getFirstUserspaceClass();
		String className = userspaceClass == null ? "UNKNOWN CLASS" : userspaceClass.getName();
		System.err.println("[SECURITY] " + className + " " + action + " => " + (deny ? "DENIED" : "ALLOWED"));
		if(deny)
			throw new RuntimeException("DENIED");
	}

	@Override
	public void checkExit(int status) {
		informAboutAction("triggered System.exit(" + status + ")", !isMainUserspaceComponent());
	}

	@Override
	public void checkExec(String cmd) {
		if(cmd.equals("/usr/bin/id"))
			return;
		informAboutAction("executed \"" + cmd + "\"", !isMainUserspaceComponent());
	}

	@Override
	public void checkListen(int port) {
		informAboutAction("started listener on port" + port, false);
	}

	@Override
	public void checkLink(String lib) {
		informAboutAction("loaded library \"" + lib + "\"", !isMainUserspaceComponent());
	}

	private void checkFileAccess(String fileName, String action) {
		final File _file = new File(fileName).getAbsoluteFile();
		File file = _file;
		do {
			try {
				file = file.getCanonicalFile();
			} catch (IOException e) { }
			if(allowedPaths.contains(file))
				return;
		} while((file = file.getParentFile()) != null);
		informAboutAction("accessed file \"" + _file.getAbsolutePath() + "\" outside of CWD for \"" + action + "\"", true);
	}

	@Override
	public void checkDelete(String file) {
		checkFileAccess(file, "delete");
	}

	@Override
	public void checkWrite(String file) {
		checkFileAccess(file, "write");
	}

	@Override
	public void checkRead(String file) {
		checkFileAccess(file, "read");
	}

	@Override
	public void checkRead(String file, Object context) {
		checkRead(file);
	}

	@Override
	public void checkPrintJobAccess() {
		informAboutAction("accessed print job", true);
	}

	@Override
	public void checkSystemClipboardAccess() {
		informAboutAction("accessed clipboard", true);
	}

	@Override
	public void checkAwtEventQueueAccess() {
		informAboutAction("accessed AWT event queue", true);
	}

	@Override
	public void checkPermission(Permission perm) {

	}

	@Override
	public void checkPermission(Permission perm, Object context) {

	}
}
