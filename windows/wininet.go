package windows

func WininetHooks(emu *WinEmulator) {
	//void InternetOpenA(
	//  LPCSTR lpszAgent,
	//  DWORD  dwAccessType,
	//  LPCSTR lpszProxy,
	//  LPCSTR lpszProxyBypass,
	//  DWORD  dwFlags
	//);
	emu.AddHook("", "InternetOpenA", &Hook{
		Parameters: []string{"a:lpszAgent", "dwAccessType", "a:lpszProxy", "a:lpszProxyBypass", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "InternetOpenW", &Hook{
		Parameters: []string{"w:lpszAgent", "dwAccessType", "w:lpszProxy", "w:lpszProxyBypass", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "InternetOpenUrlA", &Hook{
		Parameters: []string{"hInternet", "a:lpszUrl", "a:lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "InternetOpenUrlW", &Hook{
		Parameters: []string{"hInternet", "w:lpszUrl", "w:lpszHeaders", "dwHeadersLength", "dwFlags", "dwContext"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "InternetCloseHandle", &Hook{
		Parameters: []string{"hInternet"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "InternetReadFile", &Hook{
		Parameters: []string{"hFile", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

}
