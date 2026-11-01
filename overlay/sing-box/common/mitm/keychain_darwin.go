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
	"unsafe"
)

const (
	keychainService          = "io.nekohasekai.sfa.mitm"
	keychainAccount          = "ca-key"
	errSecItemNotFoundStatus = -25300
)

func keychainSet(_ string, data []byte) error {
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
		return fmt.Errorf("mitm: keychain save failed (%d)", int(status))
	}
	return nil
}

func keychainGet(_ string) ([]byte, error) {
	service := C.CString(keychainService)
	defer C.free(unsafe.Pointer(service))
	account := C.CString(keychainAccount)
	defer C.free(unsafe.Pointer(account))
	var pointer unsafe.Pointer
	var length C.size_t
	status := C.sb_keychain_get(service, account, &pointer, &length)
	if int(status) == errSecItemNotFoundStatus {
		return nil, nil
	}
	if int(status) != 0 {
		return nil, fmt.Errorf("mitm: keychain load failed (%d)", int(status))
	}
	if pointer == nil {
		return nil, nil
	}
	defer C.free(pointer)
	return C.GoBytes(pointer, C.int(length)), nil
}

func keychainDelete(_ string) error {
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
