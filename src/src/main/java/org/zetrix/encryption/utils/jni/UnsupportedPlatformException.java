// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package org.zetrix.encryption.utils.jni;

/**
 * Exception thrown when the current platform cannot be detected.
 *
 * @author ZetrixChain
 */
@SuppressWarnings("serial")
public class UnsupportedPlatformException extends RuntimeException {
    public UnsupportedPlatformException(String s) {
        super(s);
    }
}
