@import UIKit;
@import Foundation;
@import MachO.dyld;

static const char *DYLIB_VERSION_STRING __attribute__((used)) = "@(#)llas-patcher 20240128. Copyright (c) 2023-2024, the Holy Constituency of the Summer Triangle.";

NSString *const PUBLIC_KEY_DEFAULT = @"<RSAKeyValue><Modulus>1r6QjkBr1hIGrgq95ZEEDnXqCYa+81hvhejsGoUcfCZ/kkngBuUbq8/rqRfoFVEZOmDRG8DKrhtfFoWQyftqycCrQj8ELQeGCQJFtdXg+eljb3HDP8Zzzh+9YXJHNIswCYfMFYXlBHP90QniFfZqfERVSqK9V1uJU8EyxHMismU=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

typedef void (*initializer_func)(int); 
typedef struct {
	// something along the lines of
	// if ((DAT_10572360c <-- off_init_flag & 1) == 0) {
	//     FUN_101035ed4 <-- off_init_func(0xd9f5 <-- param);
	//     DAT_10572360c = 1;
	// }
	uintptr_t off_init_flag;
	uintptr_t off_init_func;
	uint32_t param;
} ensure_initialized_t;

typedef struct {
	// rsa key StringLiteral
	uintptr_t rsa_key;
	// endpoint StringLiteral
	uintptr_t server_endpoint;
	// Constant class vars (for sqlite keys, not used)
	uintptr_t const_typeinfo;
	ensure_initialized_t *initializers; 
} offsets_t;

ensure_initialized_t _inits_GL[] = {
	{ 0x105733e30, 0x101037c34, 0x3d55 }, // RSAKey
	{ 0x10573919d, 0x101037c34, 0xda00 }, // ServerEndpoint
	//{ 0x105738d09, 0x101037c34, 0x37bc }, // Constant
	{ 0, 0, 0 }
};

ensure_initialized_t _inits_JP[] = {
	// DMCryptography.CreateRSAProvider
	{ 0x10571e2b0, 0x101035ed4, 0x3d53 }, // RSAKey
	// ServerConfig..cctor
	{ 0x10572360c, 0x101035ed4, 0xd9f5 }, // ServerEndpoint
	//{ 0x105738d09, 0x101037c34, 0x37bc }, // Constant
	{ 0, 0, 0 }
};

offsets_t offsets_GL = {
	.rsa_key = 0x1059071b0,
	.server_endpoint = 0x10590a550,
	.const_typeinfo = 0x105868d58,
	.initializers = _inits_GL
};

offsets_t offsets_JP = {
	.rsa_key = 0x1058f0f50,
	.server_endpoint = 0x1058f42e8,
	.const_typeinfo = 0x105853558,
	.initializers = _inits_JP
};


typedef struct __attribute__((packed)) {
	uint64_t type_tag;
	uint64_t zero;
	int32_t length;
} net_string_head_t;

void *moveStringToHeap(NSString *s, uint64_t type_tag) {
	NSData *utf16 = [s dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
	int32_t len = (int32_t)utf16.length / 2;
	int32_t storageLen = utf16.length + 2;
	if (len % 2 == 0) {
		storageLen += 4;
	}

	net_string_head_t *netstring = calloc(sizeof(net_string_head_t) + utf16.length, 1);
	netstring->type_tag = type_tag;
	netstring->zero = 0;
	netstring->length = len;

	memcpy((uint8_t *)(netstring + 1), utf16.bytes, utf16.length);
	return (void *)netstring;
}

int overwriteString(NSString *s, uint8_t *dst) {
	net_string_head_t *netstring = (net_string_head_t *)dst;
	NSData *utf16 = [s dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
	int32_t len = (int32_t)utf16.length / 2;
	int32_t copy_size = (netstring->length > len) ? len : netstring->length;

	netstring->length = copy_size;
	memcpy(netstring + 1, utf16.bytes, copy_size * 2);
	return copy_size == len;
}


%hook UnityAppController

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary<UIApplicationLaunchOptionsKey, id> *)launchOptions {
	BOOL res = %orig;
	uintptr_t slide = _dyld_get_image_vmaddr_slide(0);
	offsets_t *offsets;

	if ([NSBundle.mainBundle.bundleIdentifier hasPrefix:@"com.klab.lovelive.allstars.global"]) {
		NSLog(@"Initializing for SIFAS GL, bundleIdentifier: %@", NSBundle.mainBundle.bundleIdentifier);
		offsets = &offsets_GL;
	} else {
		NSLog(@"Initializing for SIFAS JP, bundleIdentifier: %@", NSBundle.mainBundle.bundleIdentifier);
		offsets = &offsets_JP;
	}

	for (ensure_initialized_t *def = offsets->initializers; def->param != 0; ++def) {
		uint8_t *redptr = (uint8_t *)(slide + def->off_init_flag);
		if (!(*redptr)) {
			((initializer_func)(slide + def->off_init_func))(def->param);
			*redptr = 1;
		}
	}

	NSUserDefaults *settings = [NSUserDefaults standardUserDefaults];
	NSString *re_ep = [settings stringForKey:@"ServerEndpoint"];
	if (re_ep) {
		NSLog(@"Patching server endpoint: %@", re_ep);
		uint64_t **endpoint_ptr = (uint64_t **)(slide + offsets->server_endpoint);
		overwriteString(re_ep, (uint8_t *)*endpoint_ptr);
	}

	NSString *re_key = [settings stringForKey:@"RSAKey"];
	if (re_key && [re_key length] > 0) {
		NSLog(@"Patching public key: %@", re_key);
		uint64_t **rsa_ptr = (uint64_t **)(slide + offsets->rsa_key);
		overwriteString(re_key, (uint8_t *)*rsa_ptr);
	}

	// the commented code below does not work

	// BOOL wantLegacySqliteKeys = [settings boolForKey:@"WantLegacySqliteKeys"];
	// uint32_t p0 = 0x49e66da3, p1 = 0x59e1e89a, p2 = 0x24ebb207;
	// if (wantLegacySqliteKeys) {
	// 	p0 = 0x06856c49;
	// 	p1 = 0x3aa19541;
	// 	p2 = 0x5f13a7c1;
	// }

	// NSLog(@"Patching sqlite keys (want 3.11 keys: %d)", (int)wantLegacySqliteKeys);
	// void *typeinfo = *(void **)(slide + offsets->const_typeinfo);
	// uint32_t *constant_ivars = (uint32_t *)(typeinfo + 0xb8);
	// constant_ivars[0] = p0;
	// constant_ivars[1] = p1;
	// constant_ivars[2] = p2;

	return res;
}

%end