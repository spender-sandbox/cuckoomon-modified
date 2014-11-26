/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include "ntapi.h"
#include <windns.h>
#include <wininet.h>
#include "hooking.h"
#include "log.h"
#include "pipe.h"

HOOKDEF(HINTERNET, WINAPI, WinHttpOpen,
	_In_opt_ LPCWSTR pwszUserAgent,
	_In_ DWORD dwAccessType,
	_In_ LPCWSTR pwszProxyName,
	_In_ LPCWSTR pwszProxyBypass,
	_In_ DWORD dwFlags
) {
	HINTERNET ret = Old_WinHttpOpen(pwszUserAgent, dwAccessType, pwszProxyName, pwszProxyBypass, dwFlags);
	LOQ_nonnull("network", "uuupp", "UserAgent", pwszUserAgent, "ProxyName", pwszProxyName, "ProxyBypass", pwszProxyBypass, "AccessType", dwAccessType, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpGetIEProxyConfigForCurrentUser,
	_Inout_ LPVOID pProxyConfig // WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *
) {
	BOOL ret = Old_WinHttpGetIEProxyConfigForCurrentUser(pProxyConfig);
	LOQ_bool("network", "");
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpGetProxyForUrl,
	_In_ HINTERNET hSession,
	_In_ LPCWSTR lpcwszUrl,
	_In_ LPVOID pAutoProxyOptions, // WINHTTP_AUTOPROXY_OPTIONS *
	_Out_ LPVOID pProxyInfo // WINHTTP_PROXY_INFO *
) {
	BOOL ret = Old_WinHttpGetProxyForUrl(hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
	LOQ_bool("network", "pu", "SessionHandle", hSession, "Url", lpcwszUrl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpSetOption,
	_In_ HINTERNET hInternet,
	_In_ DWORD dwOption,
	_In_ LPVOID lpBuffer,
	_In_ DWORD dwBufferLength
) {
	BOOL ret = Old_WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
	LOQ_bool("network", "ppb", "InternetHandle", hInternet, "Option", dwOption, "Buffer", dwBufferLength, lpBuffer);
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, WinHttpConnect,
	_In_ HINTERNET hSession,
	_In_ LPCWSTR pswzServerName,
	_In_ INTERNET_PORT nServerPort,
	_Reserved_ DWORD dwReserved
) {
	HINTERNET ret = Old_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
	LOQ_nonnull("network", "pul", "SessionHandle", hSession, "ServerName", pswzServerName, "ServerPort", nServerPort);
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, WinHttpOpenRequest,
	_In_  HINTERNET hConnect,
	_In_  LPCWSTR pwszVerb,
	_In_  LPCWSTR pwszObjectName,
	_In_  LPCWSTR pwszVersion,
	_In_  LPCWSTR pwszReferrer,
	_In_  LPCWSTR *ppwszAcceptTypes,
	_In_  DWORD dwFlags
) {
	HINTERNET ret = Old_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
	LOQ_nonnull("network", "puuuup", "InternetHandle", hConnect, "Verb", pwszVerb, "ObjectName", pwszObjectName, "Version", pwszVersion, "Referrer", pwszReferrer, "Flags", dwFlags);
	return ret;
}

HOOKDEF(BOOL, WINAPI, WinHttpSetTimeouts,
	_In_  HINTERNET hInternet,
	_In_  int dwResolveTimeout,
	_In_  int dwConnectTimeout,
	_In_  int dwSendTimeout,
	_In_  int dwReceiveTimeout
) {
	BOOL ret = Old_WinHttpSetTimeouts(hInternet, dwResolveTimeout, dwConnectTimeout, dwSendTimeout, dwReceiveTimeout);
	LOQ_bool("network", "piiii", "InternetHandle", hInternet, "ResolveTimeout", dwResolveTimeout, "ConnectTimeout", dwConnectTimeout, "SendTimeout", dwSendTimeout, "ReceiveTimeout", dwReceiveTimeout);
	return ret;
}

/* if servername is NULL, then this isn't network related, but for simplicity sake we'll log it as such */
HOOKDEF(DWORD, WINAPI, NetUserGetInfo,
	_In_ LPCWSTR servername,
	_In_ LPCWSTR username,
	_In_ DWORD level,
	_Out_ LPBYTE *bufptr
) {
	DWORD ret = Old_NetUserGetInfo(servername, username, level, bufptr);
	LOQ_zero("network", "uul", "ServerName", servername, "UserName", username, "Level", level);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, ObtainUserAgentString,
	_In_ DWORD dwOption,
	_Out_ LPSTR pcszUAOut,
	_Out_ DWORD *cbSize
) {
	HRESULT ret = Old_ObtainUserAgentString(dwOption, pcszUAOut, cbSize);
	LOQ_hresult("network", "s", "UserAgent", pcszUAOut);
	return ret;
}

HOOKDEF(HRESULT, WINAPI, URLDownloadToFileW,
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
) {
    HRESULT ret = Old_URLDownloadToFileW(pCaller, szURL, szFileName,
        dwReserved, lpfnCB);
    LOQ_hresult("network", "uF", "URL", szURL, "FileName", szFileName);
    if(ret == S_OK) {
        pipe("FILE_NEW:%S", -1, szFileName);
    }
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetGetConnectedState,
	_Out_ LPDWORD lpdwFlags,
	_In_ DWORD dwReserved
) {
	BOOL ret = Old_InternetGetConnectedState(lpdwFlags, dwReserved);
	LOQ_bool("network", "");
	return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenA,
    _In_  LPCTSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPCTSTR lpszProxyName,
    _In_  LPCTSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenA(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);
    LOQ_nonnull("network", "spssp", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenW,
    _In_  LPWSTR lpszAgent,
    _In_  DWORD dwAccessType,
    _In_  LPWSTR lpszProxyName,
    _In_  LPWSTR lpszProxyBypass,
    _In_  DWORD dwFlags
) {
    HINTERNET ret = Old_InternetOpenW(lpszAgent, dwAccessType, lpszProxyName,
        lpszProxyBypass, dwFlags);
    LOQ_nonnull("network", "upuup", "Agent", lpszAgent, "AccessType", dwAccessType,
        "ProxyName", lpszProxyName, "ProxyBypass", lpszProxyBypass,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectA,
    _In_  HINTERNET hInternet,
    _In_  LPCTSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPCTSTR lpszUsername,
    _In_  LPCTSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetConnectA(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ_nonnull("network", "pslsslp", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetConnectW,
    _In_  HINTERNET hInternet,
    _In_  LPWSTR lpszServerName,
    _In_  INTERNET_PORT nServerPort,
    _In_  LPWSTR lpszUsername,
    _In_  LPWSTR lpszPassword,
    _In_  DWORD dwService,
    _In_  DWORD dwFlags,
    _In_  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetConnectW(hInternet, lpszServerName,
        nServerPort, lpszUsername, lpszPassword, dwService, dwFlags,
        dwContext);
    LOQ_nonnull("network", "puluulp", "InternetHandle", hInternet, "ServerName", lpszServerName,
        "ServerPort", nServerPort, "Username", lpszUsername,
        "Password", lpszPassword, "Service", dwService, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlA,
    __in  HINTERNET hInternet,
    __in  LPCTSTR lpszUrl,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    if(dwHeadersLength == (DWORD) -1)
		dwHeadersLength = strlen(lpszHeaders);
    LOQ_nonnull("network", "psSp", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, InternetOpenUrlW,
    __in  HINTERNET hInternet,
    __in  LPWSTR lpszUrl,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders,
        dwHeadersLength, dwFlags, dwContext);
    LOQ_nonnull("network", "puUp", "ConnectionHandle", hInternet, "URL", lpszUrl,
        "Headers", dwHeadersLength, lpszHeaders, "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestA,
    __in  HINTERNET hConnect,
    __in  LPCTSTR lpszVerb,
    __in  LPCTSTR lpszObjectName,
    __in  LPCTSTR lpszVersion,
    __in  LPCTSTR lpszReferer,
    __in  LPCTSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_HttpOpenRequestA(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ_nonnull("network", "psp", "InternetHandle", hConnect, "Path", lpszObjectName,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(HINTERNET, WINAPI, HttpOpenRequestW,
    __in  HINTERNET hConnect,
    __in  LPWSTR lpszVerb,
    __in  LPWSTR lpszObjectName,
    __in  LPWSTR lpszVersion,
    __in  LPWSTR lpszReferer,
    __in  LPWSTR *lplpszAcceptTypes,
    __in  DWORD dwFlags,
    __in  DWORD_PTR dwContext
) {
    HINTERNET ret = Old_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName,
        lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    LOQ_nonnull("network", "pup", "InternetHandle", hConnect, "Path", lpszObjectName,
        "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestA,
    __in  HINTERNET hRequest,
    __in  LPCTSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
) {
    BOOL ret = Old_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);
    if(dwHeadersLength == (DWORD) -1 && lpszHeaders != NULL) dwHeadersLength = strlen(lpszHeaders);
    LOQ_bool("network", "pSb", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, HttpSendRequestW,
    __in  HINTERNET hRequest,
    __in  LPWSTR lpszHeaders,
    __in  DWORD dwHeadersLength,
    __in  LPVOID lpOptional,
    __in  DWORD dwOptionalLength
) {
    BOOL ret = Old_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength);
    LOQ_bool("network", "pUb", "RequestHandle", hRequest,
        "Headers", dwHeadersLength, lpszHeaders,
        "PostData", dwOptionalLength, lpOptional);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetReadFile,
    _In_   HINTERNET hFile,
    _Out_  LPVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToRead,
    _Out_  LPDWORD lpdwNumberOfBytesRead
) {
    BOOL ret = Old_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead);
    LOQ_bool("network", "pB", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesRead, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetWriteFile,
    _In_   HINTERNET hFile,
    _In_   LPCVOID lpBuffer,
    _In_   DWORD dwNumberOfBytesToWrite,
    _Out_  LPDWORD lpdwNumberOfBytesWritten
) {
    BOOL ret = Old_InternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite,
        lpdwNumberOfBytesWritten);
    LOQ_bool("network", "pB", "InternetHandle", hFile,
        "Buffer", lpdwNumberOfBytesWritten, lpBuffer);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetCloseHandle,
    _In_  HINTERNET hInternet
) {
    BOOL ret = Old_InternetCloseHandle(hInternet);
    LOQ_bool("network", "p", "InternetHandle", hInternet);
    return ret;
}

HOOKDEF(BOOL, WINAPI, InternetCrackUrlA,
	_In_ LPCSTR lpszUrl,
	_In_ DWORD dwUrlLength,
	_In_ DWORD dwFlags,
	_Inout_ LPURL_COMPONENTSA lpUrlComponents
) {
	BOOL ret = Old_InternetCrackUrlA(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
	LOQ_bool("network", "s", "Url", lpszUrl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, InternetCrackUrlW,
	_In_ LPCWSTR lpszUrl,
	_In_ DWORD dwUrlLength,
	_In_ DWORD dwFlags,
	_Inout_ LPURL_COMPONENTSW lpUrlComponents
) {
	BOOL ret = Old_InternetCrackUrlW(lpszUrl, dwUrlLength, dwFlags, lpUrlComponents);
	LOQ_bool("network", "u", "Url", lpszUrl);
	return ret;
}

HOOKDEF(BOOL, WINAPI, InternetSetOptionA,
	_In_ HINTERNET hInternet,
	_In_ DWORD dwOption,
	_In_ LPVOID lpBuffer,
	_In_ DWORD dwBufferLength
) {
	BOOL ret = Old_InternetSetOptionA(hInternet, dwOption, lpBuffer, dwBufferLength);
	// when logging the buffer, remember the special handling of dwBufferLength when lpBuffer holds a string vs other content
	LOQ_bool("network", "pp", "InternetHandle", hInternet, "Option", dwOption);
	return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_A,
    __in         PCSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    DNS_STATUS ret = Old_DnsQuery_A(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ_zero("network", "sip", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_UTF8,
    __in         LPBYTE lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    DNS_STATUS ret = Old_DnsQuery_UTF8(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ_zero("network", "sip", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(DNS_STATUS, WINAPI, DnsQuery_W,
    __in         PWSTR lpstrName,
    __in         WORD wType,
    __in         DWORD Options,
    __inout_opt  PVOID pExtra,
    __out_opt    PDNS_RECORD *ppQueryResultsSet,
    __out_opt    PVOID *pReserved
) {
    DNS_STATUS ret = Old_DnsQuery_W(lpstrName, wType, Options, pExtra,
        ppQueryResultsSet, pReserved);
    LOQ_zero("network", "uip", "Name", lpstrName, "Type", wType, "Options", Options);
    return ret;
}

HOOKDEF(int, WINAPI, getaddrinfo,
    _In_opt_  PCSTR pNodeName,
    _In_opt_  PCSTR pServiceName,
    _In_opt_  const ADDRINFOA *pHints,
    _Out_     PADDRINFOA *ppResult
) {
    int ret = Old_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    LOQ_zero("network", "ss", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}

HOOKDEF(int, WINAPI, GetAddrInfoW,
    _In_opt_  PCWSTR pNodeName,
    _In_opt_  PCWSTR pServiceName,
    _In_opt_  const ADDRINFOW *pHints,
    _Out_     PADDRINFOW *ppResult
) {
    int ret = Old_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    LOQ_zero("network", "uu", "NodeName", pNodeName, "ServiceName", pServiceName);
    return ret;
}
