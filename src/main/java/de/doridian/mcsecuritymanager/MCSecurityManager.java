package de.doridian.mcsecuritymanager;

import java.io.File;
import java.io.IOException;
import java.security.Permission;
import java.util.*;

public class MCSecurityManager extends SecurityManager {
	private final Set<ClassLoader> systemClassLoader = Collections.newSetFromMap(new IdentityHashMap<ClassLoader, Boolean>());

	private final Thread ownThread;

	private final String proxyHost;
	private final int proxyPort;

	private final Set<File> allowedPaths = new HashSet<File>();
	private final Set<File> allowedPathsRead = new HashSet<File>();

	private final Set<String> validLibs = new HashSet<String>();

	private final Set<String> blacklistedRuntimePermissions = new HashSet<String>();

	MCSecurityManager(ClassLoader protectedClassLoader) {
		this.systemClassLoader.add(this.getClass().getClassLoader());
		this.systemClassLoader.add(ClassLoader.getSystemClassLoader());

		ownThread = Thread.currentThread();

		int pport = -1;
		try {
			pport = Integer.parseInt(System.getProperty("http.proxyPort"));
		} catch (Exception e) { }
		proxyHost = System.getProperty("http.proxyHost");
		proxyPort = pport;

		addCanonicalAllowedFile(System.getProperty("user.dir"), true);
		addCanonicalAllowedFile(System.getProperty("java.io.tmpdir"), true);
		addCanonicalAllowedFile(System.getProperty("java.home"));
		addCanonicalAllowedFile("/usr/share/javazi/ZoneInfoMappings");
		addCanonicalAllowedFile("/proc");
		addCanonicalAllowedFile("/sys");
		addCanonicalAllowedFile("/dev/random");
		addCanonicalAllowedFile("/dev/urandom");
		addCanonicalAllowedFile("/etc/inputrc");

		validLibs.add("nio");
		validLibs.add("net");
		validLibs.add("management");

		blacklistedRuntimePermissions.add("setSecurityManager");
		blacklistedRuntimePermissions.add("createSecurityManager");
		blacklistedRuntimePermissions.add("usePolicy");
		//blacklistedRuntimePermissions.add("readFileDescriptor");
		//blacklistedRuntimePermissions.add("writeFileDescriptor");
	}

	private void addCanonicalAllowedFile(String _file) {
		addCanonicalAllowedFile(_file, false);
	}

	private void addCanonicalAllowedFile(String _file, boolean allowWrite) {
		try {
			File file = new File(_file).getCanonicalFile();
			if(allowWrite)
				allowedPaths.add(file);
			allowedPathsRead.add(file);
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
		return userspaceClass != null && userspaceClass.getClassLoader() == ownThread.getContextClassLoader();
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
		if(!deny && className.equals("net.minecraft.util.com.mojang.authlib.HttpAuthenticationService"))
			return;
		System.err.println("[SECURITY] " + className + " " + action + " => " + (deny ? "DENIED" : "ALLOWED"));
		if(deny)
			throw new UnsatisfiedLinkError("DENIED");
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
		if(port < 1)
			return;
		informAboutAction("started listener on port " + port, false);
	}

	@Override
	public void checkLink(String lib) {
		if(validLibs.contains(lib))
			return;
		informAboutAction("loaded library \"" + lib + "\"", !isMainUserspaceComponent());
	}

	private final Object checkFileLock = new Object();
	private boolean fileCheckDisabled = false;

	private void checkFileAccess(String fileName, String action, Set<File> allowedRootPaths) {
		final File _file = new File(fileName).getAbsoluteFile();
		synchronized (checkFileLock) {
			if(fileCheckDisabled)
				return;
			fileCheckDisabled = true;
			if(_file.isDirectory()) {
				fileCheckDisabled = false;
				return;
			}
			fileCheckDisabled = false;
		}
		File file = _file;
		do {
			try {
				file = file.getCanonicalFile();
			} catch (IOException e) { }
			if(allowedRootPaths.contains(file))
				return;
		} while((file = file.getParentFile()) != null);
		informAboutAction("accessed file \"" + _file.getAbsolutePath() + "\" outside of CWD for \"" + action + "\"", true);
	}

	@Override
	public void checkDelete(String file) {
		checkFileAccess(file, "delete", allowedPaths);
	}

	@Override
	public void checkWrite(String file) {
		checkFileAccess(file, "write", allowedPaths);
	}

	@Override
	public void checkRead(String file) {
		checkFileAccess(file, "read", allowedPathsRead);
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
		if(perm instanceof RuntimePermission) {
			RuntimePermission rtPerm = (RuntimePermission)perm;
			String rtPermName = rtPerm.getName();
			if(blacklistedRuntimePermissions.contains(rtPermName))
				informAboutAction("used RuntimePermission \"" + rtPermName + "\"", true);
			if(rtPermName.startsWith("defineClassInPackage.") && SecurityMain.isInternalPackage(rtPermName.substring(21)))
				informAboutAction("defined class in internal package \"" + rtPermName.substring(21) + "\"", !isMainUserspaceComponent());
		}
	}

	@Override
	public void checkPermission(Permission perm, Object context) {
		checkPermission(perm);
	}
}
