package de.doridian.mcsecuritymanager;

import java.net.URL;
import java.net.URLClassLoader;

public class MCSecurityClassLoader extends URLClassLoader {
	MCSecurityClassLoader(URL[] urls) {
		super(urls);
	}
}
