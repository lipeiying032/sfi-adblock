//go:build darwin && cgo

package mitm

/*
#cgo LDFLAGS: -framework Security -framework Foundation

#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static int sb_keychain_set(const char *service, const char *account, const void *bytes, size_t length) {
	CFStringRef serviceRef = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef accountRef = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	CFDataRef dataRef = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)bytes, (CFIndex)length);

	const void *baseKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
	const void *baseValues[] = { kSecClassGenericPassword, serviceRef, accountRef };
	CFDictionaryRef baseQuery = CFDictionaryCreate(kCFAllocatorDefault, baseKeys, baseValues, 3,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	const void *updateKeys[] = { kSecValueData };
	const void *updateValues[] = { dataRef };
	CFDictionaryRef update = CFDictionaryCreate(kCFAllocatorDefault, updateKeys, updateValues, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	OSStatus status = SecItemUpdate(baseQuery, update);
	if (status == errSecItemNotFound) {
		const void *addKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccessible };
		const void *addValues[] = { kSecClassGenericPassword, serviceRef, accountRef, dataRef,
			kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly };
		CFDictionaryRef add = CFDictionaryCreate(kCFAllocatorDefault, addKeys, addValues, 5,
			&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		status = SecItemAdd(add, NULL);
		CFRelease(add);
	}

	CFRelease(update);
	CFRelease(baseQuery);
	CFRelease(dataRef);
	CFRelease(accountRef);
	CFRelease(serviceRef);
	return (int)status;
}

static int sb_keychain_get(const char *service, const char *account, void **data, size_t *length) {
	CFStringRef serviceRef = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef accountRef = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);

	const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
	const void *values[] = { kSecClassGenericPassword, serviceRef, accountRef, kCFBooleanTrue, kSecMatchLimitOne };
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 5,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	if (status == errSecSuccess && result != NULL) {
		CFDataRef dataRef = (CFDataRef)result;
		CFIndex dataLength = CFDataGetLength(dataRef);
		void *buffer = malloc((size_t)dataLength);
		if (buffer == NULL) {
			status = errSecAllocate;
		} else {
			memcpy(buffer, CFDataGetBytePtr(dataRef), (size_t)dataLength);
			*data = buffer;
			*length = (size_t)dataLength;
		}
		CFRelease(result);
	}

	CFRelease(query);
	CFRelease(accountRef);
	CFRelease(serviceRef);
	return (int)status;
}

static int sb_ca_trusted(const void *bytes, size_t length) {
	CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)bytes, (CFIndex)length);
	if (data == NULL) {
		return -1;
	}
	SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data);
	CFRelease(data);
	if (certificate == NULL) {
		return -1;
	}
	SecPolicyRef policy = SecPolicyCreateBasicX509();
	SecTrustRef trust = NULL;
	OSStatus status = SecTrustCreateWithCertificates(certificate, policy, &trust);
	CFRelease(policy);
	CFRelease(certificate);
	if (status != errSecSuccess || trust == NULL) {
		return -1;
	}
	CFErrorRef error = NULL;
	int trusted = SecTrustEvaluateWithError(trust, &error) ? 1 : 0;
	if (error != NULL) {
		CFRelease(error);
	}
	CFRelease(trust);
	return trusted;
}

static int sb_keychain_delete(const char *service, const char *account) {
	CFStringRef serviceRef = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef accountRef = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
	const void *values[] = { kSecClassGenericPassword, serviceRef, accountRef };
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 3,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	CFRelease(accountRef);
	CFRelease(serviceRef);
	return (int)status;
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

const (
	keychainService          = "io.nekohasekai.sfa.mitm"
	keychainAccount          = "ca-key"
	errSecItemNotFoundStatus = -25300
	errSecMissingEntitlement = -34018
)

// Unsigned / re-signed builds may not carry the keychain entitlement. In that
// case the private key falls back to a 0600 file inside the app group, which is
// still only reachable from the app and its network extension.
func keychainFallbackPath(dir string) string {
	return filepath.Join(dir, "ca.key")
}

func keychainFallbackWrite(dir string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(keychainFallbackPath(dir), data, 0o600)
}

func keychainFallbackRead(dir string) ([]byte, error) {
	data, err := os.ReadFile(keychainFallbackPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

func keychainFallbackDelete(dir string) {
	_ = os.Remove(keychainFallbackPath(dir))
}

func keychainSet(dir string, data []byte) error {
	service := C.CString(keychainService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(keychainAccount)
	defer C.free(unsafe.Pointer(account))
	var pointer unsafe.Pointer
	if len(data) > 0 {
		pointer = C.CBytes(data)
		defer C.free(pointer)
	}
	status := C.sb_keychain_set(service, account, pointer, C.size_t(len(data)))
	if int(status) != 0 {
		if int(status) == errSecMissingEntitlement {
			if fallbackErr := keychainFallbackWrite(dir, data); fallbackErr == nil {
				return nil
			}
		}
		return fmt.Errorf("mitm: keychain save failed (%d)", int(status))
	}
	keychainFallbackDelete(dir)
	return nil
}

func keychainGet(dir string) ([]byte, error) {
	service := C.CString(keychainService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(keychainAccount)
	defer C.free(unsafe.Pointer(account))
	var pointer unsafe.Pointer
	var length C.size_t
	status := C.sb_keychain_get(service, account, &pointer, &length)
	if int(status) == errSecItemNotFoundStatus || pointer == nil {
		return keychainFallbackRead(dir)
	}
	if int(status) != 0 {
		if int(status) == errSecMissingEntitlement {
			return keychainFallbackRead(dir)
		}
		return nil, fmt.Errorf("mitm: keychain load failed (%d)", int(status))
	}
	defer C.free(pointer)
	return C.GoBytes(pointer, C.int(length)), nil
}

// caTrustState reports whether the generated root CA is installed and fully
// trusted: 1 trusted, 0 not trusted, -1 unknown.
func caTrustState(der []byte) int {
	if len(der) == 0 {
		return -1
	}
	buffer := C.CBytes(der)
	defer C.free(buffer)
	return int(C.sb_ca_trusted(buffer, C.size_t(len(der))))
}

func keychainDelete(dir string) error {
	keychainFallbackDelete(dir)
	service := C.CString(keychainService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(keychainAccount)
	defer C.free(unsafe.Pointer(account))
	status := C.sb_keychain_delete(service, account)
	if int(status) != 0 && int(status) != errSecItemNotFoundStatus {
		return fmt.Errorf("mitm: keychain delete failed (%d)", int(status))
	}
	return nil
}
