#pragma once
#include <string>
#include <Windows.h>

namespace Red {
	class Exception {
	private:
		std::wstring errorMessage;
		unsigned int errorCode;

	public:
		Exception(unsigned int code, const wchar_t* format, ...);

		const wchar_t* What();
		unsigned int Code();
	};

	class Butler {
	private:
		HANDLE hDriver;
		std::wstring deviceName;

	public:
		Butler();
		Butler(std::wstring deviceName);

		bool IsOpen();

		void Open();
		void Close();

		void SetState(bool state);
		bool GetState();

		void ProtectProcess(DWORD dwProcessId);
		void UnprotectProcess(DWORD dwProcessId);
		bool IsProtected(DWORD dwProcessId);

		void ExcludeProcess(DWORD dwProcessId);
		void UnexcludeProcess(DWORD dwProcessId);
		bool IsExcluded(DWORD dwProcessId);

		void ClearProcessAttributes(DWORD dwProcessId);
		void InjectDLL(DWORD dwProcessId, std::wstring dllPath);

		ULONG HideFile(std::wstring filePath);
		void UnhideFile(ULONG uObjectId);
		void UnhideAllFiles();

		ULONG HideDirectory(std::wstring directoryPath);
		void UnhideDirectory(ULONG uObjectId);
		void UNhideAllDirectories();
	};
}